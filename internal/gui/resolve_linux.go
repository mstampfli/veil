//go:build linux

package gui

import (
	"os/exec"
	"strings"

	"github.com/mstampfli/veil/internal/engine"
)

// resolveHostThroughSession runs `ip netns exec <ns> getent hosts <host>`
// to look up a name using whatever resolver the namespace has configured.
// Returns the first IPv4 found, or "" on error.
func resolveHostThroughSession(s *engine.Session, host string) (string, error) {
	ns := nsNameFromSession(s)
	if ns == "" {
		// Host network — use the system resolver.
		out, err := exec.Command("getent", "hosts", host).Output()
		if err != nil {
			return "", err
		}
		fields := strings.Fields(strings.TrimSpace(string(out)))
		if len(fields) >= 1 {
			return fields[0], nil
		}
		return "", nil
	}
	out, err := exec.Command("ip", "netns", "exec", ns, "getent", "hosts", host).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) >= 1 {
		return fields[0], nil
	}
	return "", nil
}
