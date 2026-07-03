// Package all imports every backend so their init() functions register
// them with the backends registry. Import this package with the blank
// identifier from CLI/GUI entrypoints.
package all

import (
	_ "github.com/mstampfli/veil/internal/backends/direct"
	_ "github.com/mstampfli/veil/internal/backends/httpproxy"
	_ "github.com/mstampfli/veil/internal/backends/openvpn"
	_ "github.com/mstampfli/veil/internal/backends/socks5"
	_ "github.com/mstampfli/veil/internal/backends/tlsmitm"
	_ "github.com/mstampfli/veil/internal/backends/tor"
	_ "github.com/mstampfli/veil/internal/backends/wireguard"
)
