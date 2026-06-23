//go:build !linux

package gui

import (
	"net"

	"github.com/mstampfli/veil/internal/engine"
)

func resolveHostThroughSession(s *engine.Session, host string) (string, error) {
	// On non-Linux platforms we have no namespace to enter — best
	// effort: use the host resolver.
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return "", err
	}
	return addrs[0], nil
}
