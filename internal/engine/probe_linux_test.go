//go:build linux

package engine

import "testing"

func TestNonLoopbackListeners(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{
			// Real `ss -tlnH` from a tor profile netns: tor's Socks/
			// Control/DNS ports, all loopback -> must NOT be flagged
			// (this is the false-positive the fix closes).
			name: "tor loopback ports",
			in: "LISTEN 0      4096   127.0.0.1:54329 0.0.0.0:*\n" +
				"LISTEN 0      4096   127.0.0.1:57032 0.0.0.0:*\n" +
				"LISTEN 0      4096   127.0.0.1:50450 0.0.0.0:*\n",
			want: 0,
		},
		{name: "empty", in: "", want: 0},
		{name: "ipv6 loopback", in: "LISTEN 0 4096 [::1]:9050 [::]:*\n", want: 0},
		{
			name: "wildcard v4 is flagged",
			in:   "LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*\n",
			want: 1,
		},
		{
			name: "wildcard v6 is flagged",
			in:   "LISTEN 0 4096 [::]:8080 [::]:*\n",
			want: 1,
		},
		{
			name: "routable veth IP is flagged",
			in:   "LISTEN 0 4096 10.77.0.2:9000 0.0.0.0:*\n",
			want: 1,
		},
		{
			name: "mixed: only the routable one is flagged",
			in: "LISTEN 0 4096 127.0.0.1:9050 0.0.0.0:*\n" +
				"LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*\n",
			want: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nonLoopbackListeners(c.in)
			if len(got) != c.want {
				t.Errorf("got %d flagged (%v), want %d", len(got), got, c.want)
			}
		})
	}
}
