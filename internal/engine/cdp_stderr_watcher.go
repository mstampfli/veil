//go:build linux

package engine

import (
	"bytes"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/mstampfli/veil/internal/logger"
)

// devToolsListeningRE matches the "DevTools listening on ws://..."
// stderr line that Chromium prints once its DevTools server has
// fully bound a port (after --remote-debugging-port=0). Same regex
// Puppeteer/Playwright/ChromeDriver use.
var devToolsListeningRE = regexp.MustCompile(`DevTools listening on (ws://[^\s]+)`)

// devToolsURLWatcher is an io.Writer that tees stderr through to
// the underlying log AND scans for the DevTools URL line. Once
// matched, populates st.cdpWSURL + st.cdpPort and closes
// st.cdpReady so probes can proceed without waiting on the
// /json/version HTTP endpoint.
type devToolsURLWatcher struct {
	mu  sync.Mutex
	buf bytes.Buffer
	st  *linuxState
}

func newDevToolsURLWatcher(st *linuxState) *devToolsURLWatcher {
	return &devToolsURLWatcher{st: st}
}

func (w *devToolsURLWatcher) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	// Cap buffer growth in the no-match case so a chatty browser
	// doesn't grow our buffer forever. 16 KiB is plenty for the
	// startup banner where DevTools URL appears.
	if w.buf.Len() > 16384 {
		// Keep the trailing 4 KiB in case the line is mid-flight.
		tail := w.buf.Bytes()[w.buf.Len()-4096:]
		w.buf.Reset()
		w.buf.Write(tail)
	}
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf.Next(i+1)), "\r\n")
		if w.st != nil && w.st.cdpWSURL == "" {
			if m := devToolsListeningRE.FindStringSubmatch(line); m != nil {
				ws := m[1]
				w.st.cdpWSURL = ws
				if u, err := url.Parse(ws); err == nil {
					if portStr := u.Port(); portStr != "" {
						if pn, err := strconv.Atoi(portStr); err == nil {
							w.st.cdpPort = pn
						}
					}
				}
				if w.st.cdpReady != nil {
					select {
					case <-w.st.cdpReady: // already closed
					default:
						close(w.st.cdpReady)
					}
				}
				logger.L().Info("chromium DevTools URL captured from stderr",
					"ws", ws, "port", w.st.cdpPort)
			}
		}
	}
	return len(p), nil
}
