package wireguard

import "testing"

func TestHandshakeFromUAPI(t *testing.T) {
	cases := []struct {
		name string
		uapi string
		want bool
	}{
		{
			name: "fresh device, no handshake yet",
			uapi: "private_key=00\npublic_key=ab\nendpoint=1.2.3.4:51820\n" +
				"last_handshake_time_sec=0\nlast_handshake_time_nsec=0\n",
			want: false,
		},
		{
			name: "handshake completed",
			uapi: "public_key=ab\nendpoint=1.2.3.4:51820\n" +
				"last_handshake_time_sec=1718900000\nlast_handshake_time_nsec=123\n",
			want: true,
		},
		{
			name: "no handshake field at all",
			uapi: "private_key=00\npublic_key=ab\nendpoint=1.2.3.4:51820\n",
			want: false,
		},
		{
			name: "multi-peer, second peer up",
			uapi: "public_key=aa\nlast_handshake_time_sec=0\n" +
				"public_key=bb\nlast_handshake_time_sec=42\n",
			want: true,
		},
		{
			name: "tolerates indented/CR lines",
			uapi: "  last_handshake_time_sec=7  \r\n",
			want: true,
		},
		{
			name: "empty",
			uapi: "",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := handshakeFromUAPI(tc.uapi); got != tc.want {
				t.Fatalf("handshakeFromUAPI = %v, want %v", got, tc.want)
			}
		})
	}
}
