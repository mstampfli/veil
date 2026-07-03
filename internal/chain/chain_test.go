package chain

import (
	"testing"

	"github.com/mstampfli/veil/internal/profile"
)

func TestValidate(t *testing.T) {
	wg := profile.Backend{Kind: profile.BackendWireGuard, ConfigPath: "/x"}
	ovpn := profile.Backend{Kind: profile.BackendOpenVPN, ConfigPath: "/y"}
	tor := profile.Backend{Kind: profile.BackendTor}
	socks := profile.Backend{Kind: profile.BackendSOCKS5, Host: "h", Port: 1}
	httpx := profile.Backend{Kind: profile.BackendHTTP, Host: "h", Port: 1}
	direct := profile.Backend{Kind: profile.BackendDirect}

	cases := []struct {
		name  string
		chain []profile.Backend
		ok    bool
	}{
		{"direct alone", []profile.Backend{direct}, true},
		{"socks alone", []profile.Backend{socks}, true},
		{"http alone", []profile.Backend{httpx}, true},
		{"tor alone", []profile.Backend{tor}, true},
		{"wg alone", []profile.Backend{wg}, true},
		{"ovpn alone", []profile.Backend{ovpn}, true},

		{"wg -> tor", []profile.Backend{wg, tor}, true},
		{"ovpn -> tor", []profile.Backend{ovpn, tor}, true},
		{"wg -> socks", []profile.Backend{wg, socks}, true},
		{"wg -> http", []profile.Backend{wg, httpx}, true},
		{"wg -> tor -> socks", []profile.Backend{wg, tor, socks}, true},
		{"socks -> tor", []profile.Backend{socks, tor}, true},
		{"http -> tor", []profile.Backend{httpx, tor}, true},
		{"socks -> tor -> http", []profile.Backend{socks, tor, httpx}, true},

		{"empty", nil, false},
		{"two tunnels (nested)", []profile.Backend{wg, ovpn}, true},
		{"three tunnels (nested)", []profile.Backend{wg, ovpn, wg}, true},
		{"socks -> wg (proxy before tunnel)", []profile.Backend{socks, wg}, false},
		{"tor -> wg (proxy before tunnel)", []profile.Backend{tor, wg}, false},
		{"socks -> http (chained plain proxies)", []profile.Backend{socks, httpx}, true},
		{"http -> socks (chained plain proxies)", []profile.Backend{httpx, socks}, true},
	}
	for _, c := range cases {
		err := Validate(c.chain)
		got := err == nil
		if got != c.ok {
			t.Errorf("%s: got ok=%v err=%v, want ok=%v", c.name, got, err, c.ok)
		}
	}
}

func TestSummary(t *testing.T) {
	c := []profile.Backend{
		{Kind: profile.BackendWireGuard, ConfigPath: "/x"},
		{Kind: profile.BackendTor},
	}
	got := Summary(c)
	want := "wireguard -> tor"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
