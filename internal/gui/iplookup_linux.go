//go:build linux

package gui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mstampfli/veil/internal/engine"
)

// lookupIPThroughSession drives the running browser (via CDP for
// Chromium-family / Marionette for Firefox) to fetch
// ipinfo.io/<ip>/json from inside the session's network namespace.
// The browser makes the actual HTTPS request — exit observers see a
// browser visit, not a Veil-initiated curl. Replaces the previous
// `ip netns exec ... curl` shellout, which leaked Veil's presence
// via the curl TLS fingerprint AND went out with no persona shaping.
func lookupIPThroughSession(s *engine.Session, ip string) (engine.IPInfo, error) {
	if s == nil {
		return engine.IPInfo{}, fmt.Errorf("no session")
	}
	target := "https://ipinfo.io/" + ip + "/json"
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	body, err := engine.Active().BrowserProbeIP(ctx, s, target)
	if err != nil {
		return engine.IPInfo{}, fmt.Errorf("browser probe: %w", err)
	}
	var info engine.IPInfo
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		return engine.IPInfo{IP: strings.TrimSpace(body)}, nil
	}
	return info, nil
}
