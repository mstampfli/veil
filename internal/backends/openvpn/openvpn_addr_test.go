package openvpn

import "testing"

func TestParseOvpnAddr(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantLocal string
		wantGW    string
		wantOK    bool
	}{
		{
			name:      "ptp net30 (static key / --ifconfig)",
			line:      "2026-06-19 01:13:42 net_addr_ptp_v4_add: 10.9.0.2 peer 10.9.0.1 dev tun0",
			wantLocal: "10.9.0.2/32",
			wantGW:    "10.9.0.1",
			wantOK:    true,
		},
		{
			name:      "subnet topology",
			line:      "net_addr_v4_add: 10.8.0.6/24 dev tun0",
			wantLocal: "10.8.0.6/24",
			wantGW:    "",
			wantOK:    true,
		},
		{
			name:   "unrelated line",
			line:   "Initialization Sequence Completed",
			wantOK: false,
		},
		{
			name:   "tun open line is not an address",
			line:   "TUN/TAP device tun0 opened",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc, gw, ok := parseOvpnAddr(tc.line)
			if ok != tc.wantOK || lc != tc.wantLocal || gw != tc.wantGW {
				t.Fatalf("parseOvpnAddr(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tc.line, lc, gw, ok, tc.wantLocal, tc.wantGW, tc.wantOK)
			}
		})
	}
}
