package engine

// CDP (Chrome DevTools Protocol) client for the running browser.
//
// The browser is launched with --remote-debugging-port=<port> bound to
// 127.0.0.1 *inside the netns*. From Veil's perspective:
//
//   1. We runInNetns to enter the same namespace
//   2. HTTP GET 127.0.0.1:<port>/json/version → browser-level WS URL
//   3. Send Target.createTarget({url, background:true}) → opens a tab
//      in the existing browser without disrupting the user
//   4. Target.attachToTarget → get a sessionId
//   5. Send Page.enable + wait for Page.loadEventFired (in session)
//   6. Runtime.evaluate("document.body.innerText") → JSON body
//   7. Target.closeTarget → clean up the throwaway tab
//
// The browser actually makes the network request to the URL. Veil
// never opens a TCP socket to anywhere outside the netns. The exit
// observer (e.g. ipinfo.io's logs) sees a request that is byte-for-
// byte identical to the user manually visiting the URL, because the
// request IS the user's browser making the request.
//
// All CDP traffic stays on 127.0.0.1 inside the netns — never leaves
// the namespace.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	neturl "net/url"
	"strings"
	"sync"
	"time"
)

// pickEphemeralPort lets the kernel allocate a free local port. The
// listener is closed immediately; the kernel guarantees no other
// process picked the same port between close and re-bind. Windows and
// Linux both honor this, so Chromium can bind to it for its
// --remote-debugging-port without a TOCTOU race in practice.
func pickEphemeralPort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 49321 // fallback in the dynamic range
	}
	addr := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	return addr.Port
}

// cdpProbe drives the running Chromium-family browser to fetch url
// and returns its loaded body text. On Linux the caller must be
// inside the per-profile netns (use runInNetns); on Windows there's
// no netns wrapper — call directly.
//
// Callers handle JSON parsing — this returns the raw page body.
func cdpProbe(ctx context.Context, debugPort int, target string, timeout time.Duration) (string, error) {
	return cdpProbeWithWS(ctx, debugPort, "", target, timeout)
}

// cdpProbeWithWS is cdpProbe but accepts a pre-resolved WebSocket URL.
// If wsURL is empty, falls back to /json/version HTTP discovery (the
// legacy path). If wsURL is set, uses it directly — skipping the HTTP
// round-trip is the only reliable way to talk to Brave's DevTools on
// some setups where /json/version stalls on a fully-functional WS
// server. Caller obtains wsURL from <DataDir>/DevToolsActivePort.
func cdpProbeWithWS(ctx context.Context, debugPort int, wsURL string, target string, timeout time.Duration) (string, error) {
	if debugPort == 0 {
		return "", errors.New("cdp: no debug port (browser not Chromium-family or hasn't started)")
	}
	deadline := time.Now().Add(timeout)

	browserWS := wsURL
	if browserWS == "" {
		// 1. Resolve the browser-level WebSocket URL via the debug HTTP
		//    endpoint. /json/version is the canonical entrypoint.
		verURL := fmt.Sprintf("http://127.0.0.1:%d/json/version", debugPort)
		ws, err := getBrowserWSURL(ctx, verURL, deadline)
		if err != nil {
			return "", fmt.Errorf("cdp: locate debug ws: %w", err)
		}
		browserWS = ws
	}

	// 2. Connect to the browser-level WebSocket.
	conn, err := dialWS(browserWS, fmt.Sprintf("127.0.0.1:%d", debugPort), 8*time.Second)
	if err != nil {
		return "", fmt.Errorf("cdp: dial: %w", err)
	}
	defer conn.Close()

	cli := &cdpClient{conn: conn}
	go cli.readLoop()

	// 3. Create a new background tab navigating to target. Using
	//    Target.createTarget keeps the user's existing tabs alone.
	createResp, err := cli.send(ctx, "", "Target.createTarget", map[string]any{
		"url":        target,
		"background": true,
	})
	if err != nil {
		return "", fmt.Errorf("cdp: createTarget: %w", err)
	}
	targetID, _ := createResp["targetId"].(string)
	if targetID == "" {
		return "", fmt.Errorf("cdp: createTarget: no targetId in response")
	}
	defer func() {
		_, _ = cli.send(context.Background(), "", "Target.closeTarget", map[string]any{
			"targetId": targetID,
		})
	}()

	// 4. Attach to the target (flatten=true puts the session on the
	//    same connection; required for the session-routed Page calls).
	attachResp, err := cli.send(ctx, "", "Target.attachToTarget", map[string]any{
		"targetId": targetID,
		"flatten":  true,
	})
	if err != nil {
		return "", fmt.Errorf("cdp: attachToTarget: %w", err)
	}
	sessionID, _ := attachResp["sessionId"].(string)
	if sessionID == "" {
		return "", fmt.Errorf("cdp: attachToTarget: no sessionId")
	}

	// 5. Enable Page events on the new session, then wait for
	//    loadEventFired. The createTarget itself triggered the
	//    navigation, so we just need to observe completion.
	if _, err := cli.send(ctx, sessionID, "Page.enable", nil); err != nil {
		return "", fmt.Errorf("cdp: Page.enable: %w", err)
	}
	if err := cli.waitForLoad(ctx, sessionID, 20*time.Second); err != nil {
		return "", fmt.Errorf("cdp: wait load: %w", err)
	}

	// 6. Read the page body. innerText for ipinfo's plain JSON page;
	//    for richer pages we'd want documentElement.outerHTML, but
	//    innerText is simpler and works for our use case.
	evalResp, err := cli.send(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression":    "document.body.innerText",
		"returnByValue": true,
	})
	if err != nil {
		return "", fmt.Errorf("cdp: evaluate: %w", err)
	}
	result, _ := evalResp["result"].(map[string]any)
	value, _ := result["value"].(string)
	return value, nil
}

// getBrowserWSURL fetches /json/version and returns webSocketDebuggerUrl.
//
// Uses net.DialTimeout + manual HTTP/1.1 GET instead of http.Client.
// http.Client spawns internal goroutines for connection management
// that DON'T inherit the caller's runtime.LockOSThread netns binding
// — which means our runInNetns-locked thread tells the dialer to
// connect from netns A, but the actual connect() syscall runs on a
// different OS thread in the userns child's MAIN netns where there
// is no listener on 127.0.0.1:cdpPort. Same bug as the old
// SoftReroll: a wrong-netns dial yields ECONNREFUSED with the
// listener actually bound in the right netns. Manual net.DialTimeout
// runs the connect() syscall on the calling goroutine's thread,
// which IS in the netns.
func getBrowserWSURL(ctx context.Context, target string, deadline time.Time) (string, error) {
	d := time.Until(deadline)
	if d <= 0 {
		d = 4 * time.Second
	}
	u, err := neturl.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	var lastErr error
	for time.Now().Before(deadline) {
		// Per-attempt budget. Cap to remaining time on the outer
		// deadline so we don't blow past it.
		attemptBudget := 5 * time.Second
		if rem := time.Until(deadline); rem < attemptBudget {
			attemptBudget = rem
		}
		if attemptBudget <= 100*time.Millisecond {
			break
		}
		conn, err := net.DialTimeout("tcp", host, attemptBudget)
		if err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(attemptBudget))
		// Per the Chromium source (DevToolsHttpHandler::OnJsonRequest),
		// /json/version does NOT validate Origin — only WebSocket
		// upgrades do. It DOES validate Host header (must be an IP
		// address or "localhost"); 127.0.0.1 passes that. So the
		// minimal correct request is just GET /json/version with
		// Host set. Connection: close so io.ReadAll's EOF signals
		// end of body.
		req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host +
			"\r\nConnection: close\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		raw, err := io.ReadAll(conn)
		conn.Close()
		if err != nil {
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		// Split status line + headers + body.
		split := strings.Index(string(raw), "\r\n\r\n")
		if split < 0 {
			lastErr = errors.New("no http body separator")
			time.Sleep(200 * time.Millisecond)
			continue
		}
		statusLine := strings.SplitN(string(raw[:split]), "\r\n", 2)[0]
		// "HTTP/1.1 200 OK"
		if !strings.Contains(statusLine, " 200 ") {
			lastErr = fmt.Errorf("status: %s", statusLine)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body := raw[split+4:]
		var v map[string]any
		if err := json.Unmarshal(body, &v); err != nil {
			return "", fmt.Errorf("parse json: %w (body=%q)", err, string(body))
		}
		ws, _ := v["webSocketDebuggerUrl"].(string)
		if ws == "" {
			return "", errors.New("no webSocketDebuggerUrl in /json/version")
		}
		ws = forceLocalhostInWSURL(ws)
		return ws, nil
	}
	if lastErr == nil {
		lastErr = errors.New("debug port did not respond")
	}
	return "", lastErr
}

func forceLocalhostInWSURL(ws string) string {
	const prefix = "ws://"
	if !strings.HasPrefix(ws, prefix) {
		return ws
	}
	rest := ws[len(prefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return ws
	}
	host := rest[:slash]
	colon := strings.IndexByte(host, ':')
	if colon < 0 {
		return ws
	}
	return prefix + "127.0.0.1" + host[colon:] + rest[slash:]
}

// cdpClient is a single-connection CDP request/response router.
type cdpClient struct {
	conn *wsConn

	mu      sync.Mutex
	nextID  int
	pending map[int]chan json.RawMessage

	loadMu       sync.Mutex
	loadWaiters  map[string][]chan struct{} // keyed by sessionId
	readErrOnce  sync.Once
	readErr      error
	readErrMu    sync.RWMutex
	closed       bool
}

func (c *cdpClient) readLoop() {
	for {
		raw, err := c.conn.readText()
		if err != nil {
			c.readErrOnce.Do(func() {
				c.readErrMu.Lock()
				c.readErr = err
				c.closed = true
				c.readErrMu.Unlock()
				c.failAllPending(err)
			})
			return
		}
		c.handleMessage(raw)
	}
}

func (c *cdpClient) failAllPending(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.pending {
		// Push an error-shaped message into the channel.
		errMsg, _ := json.Marshal(map[string]any{
			"id":    id,
			"error": map[string]string{"message": err.Error()},
		})
		select {
		case ch <- errMsg:
		default:
		}
		delete(c.pending, id)
	}
}

func (c *cdpClient) handleMessage(raw []byte) {
	var v struct {
		ID        int             `json:"id"`
		Method    string          `json:"method"`
		Params    json.RawMessage `json:"params"`
		SessionID string          `json:"sessionId"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return
	}
	if v.ID != 0 {
		c.mu.Lock()
		ch, ok := c.pending[v.ID]
		if ok {
			delete(c.pending, v.ID)
		}
		c.mu.Unlock()
		if ok {
			select {
			case ch <- raw:
			default:
			}
		}
		return
	}
	// Event. Care about Page.loadEventFired.
	if v.Method == "Page.loadEventFired" {
		c.loadMu.Lock()
		waiters := c.loadWaiters[v.SessionID]
		delete(c.loadWaiters, v.SessionID)
		c.loadMu.Unlock()
		for _, w := range waiters {
			close(w)
		}
	}
}

// send writes a CDP request and waits for the matching response.
// sessionID empty → browser-level call. method/params per CDP spec.
func (c *cdpClient) send(ctx context.Context, sessionID, method string, params map[string]any) (map[string]any, error) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	if c.pending == nil {
		c.pending = map[int]chan json.RawMessage{}
	}
	ch := make(chan json.RawMessage, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	msg := map[string]any{
		"id":     id,
		"method": method,
	}
	if params != nil {
		msg["params"] = params
	}
	if sessionID != "" {
		msg["sessionId"] = sessionID
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	c.readErrMu.RLock()
	closed := c.closed
	c.readErrMu.RUnlock()
	if closed {
		return nil, errors.New("cdp: connection closed")
	}
	if err := c.conn.writeText(body); err != nil {
		return nil, err
	}
	select {
	case raw := <-ch:
		var resp struct {
			Result map[string]any `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, err
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("cdp %s: %s", method, resp.Error.Message)
		}
		return resp.Result, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

// waitForLoad blocks until Page.loadEventFired arrives for sessionID.
func (c *cdpClient) waitForLoad(ctx context.Context, sessionID string, timeout time.Duration) error {
	c.loadMu.Lock()
	if c.loadWaiters == nil {
		c.loadWaiters = map[string][]chan struct{}{}
	}
	wait := make(chan struct{})
	c.loadWaiters[sessionID] = append(c.loadWaiters[sessionID], wait)
	c.loadMu.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-wait:
		return nil
	case <-timer.C:
		return errors.New("page load timeout")
	case <-ctx.Done():
		return ctx.Err()
	}
}
