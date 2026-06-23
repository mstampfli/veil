//go:build !linux

package gui

import (
	"fmt"

	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/engine"
)

func dialTorControlForGUI(s *engine.Session, port int, cookie string) (*tor.Control, error) {
	return tor.Dial(fmt.Sprintf("127.0.0.1:%d", port), cookie)
}
