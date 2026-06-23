//go:build !linux

package cli

import (
	"fmt"

	"github.com/mstampfli/veil/internal/backends/tor"
)

func dialThroughNetns(nsName, addr, cookiePath string) (*tor.Control, error) {
	return nil, fmt.Errorf("tor control dial not implemented on this OS")
}
