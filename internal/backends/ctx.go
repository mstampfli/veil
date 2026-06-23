package backends

import "context"

// ctxKey is the unexported type for backend context keys.
type ctxKey int

const (
	// namespaceKey holds the Linux network namespace name (when applicable).
	namespaceKey ctxKey = iota
	// hostGatewayKey holds the host-side veth IP (Linux engine).
	hostGatewayKey
	// profileDataDirKey holds the profile.DataDir so backends that need
	// per-profile state (tls_mitm CA) can find it without an extra
	// constructor argument.
	profileDataDirKey
	// hostLoopbackKey holds the address at which the HOST's loopback is
	// reachable from inside the profile netns. On the pasta (zero-cap)
	// uplink this differs from the host-side veth gateway: pasta maps the
	// host's 127.0.0.1 to its gateway address, which is a different subnet
	// than the inner profile veth. Backends that rewrite "localhost" to
	// reach a host-loopback service (socks5 / http) prefer this when set.
	hostLoopbackKey
)

// WithNamespace returns ctx annotated with a Linux netns name.
func WithNamespace(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, namespaceKey, name)
}

// NamespaceFrom extracts the netns name from ctx, "" if absent.
func NamespaceFrom(ctx context.Context) string {
	v, _ := ctx.Value(namespaceKey).(string)
	return v
}

// WithHostGateway annotates ctx with the host-side veth IP.
func WithHostGateway(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, hostGatewayKey, ip)
}

// HostGatewayFrom extracts the host-side veth IP, "" if absent.
func HostGatewayFrom(ctx context.Context) string {
	v, _ := ctx.Value(hostGatewayKey).(string)
	return v
}

// WithHostLoopback annotates ctx with the address at which the host's
// loopback is reachable from inside the profile netns (pasta uplink).
func WithHostLoopback(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, hostLoopbackKey, ip)
}

// HostLoopbackFrom extracts the host-loopback address, "" if absent
// (i.e. the uplink reaches host loopback via the veth gateway instead).
func HostLoopbackFrom(ctx context.Context) string {
	v, _ := ctx.Value(hostLoopbackKey).(string)
	return v
}

// WithProfileDataDir annotates ctx with the profile's data_dir.
func WithProfileDataDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, profileDataDirKey, dir)
}

// ProfileDataDirFrom extracts the profile data dir, "" if absent.
func ProfileDataDirFrom(ctx context.Context) string {
	v, _ := ctx.Value(profileDataDirKey).(string)
	return v
}
