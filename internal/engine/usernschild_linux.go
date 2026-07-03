//go:build linux

package engine

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/mstampfli/veil/internal/logger"
)

// setupNetnsDir bind-mounts writable directories over the iproute2
// state paths /run/netns AND /etc/netns inside the child's private
// mount namespace.
//
// Why this exists: inside the user-ns child we have CAP_SYS_ADMIN
// only within our own user-ns mapping. /run and /etc are owned by
// host-uid-0, which is unmapped in our user-ns, so the kernel
// rejects file creation in either subtree with EPERM regardless of
// caps. Bind-mounting our own writable directories on top —
// possible because we cloned with CLONE_NEWNS — lets the existing
// engine code do its mkdirs and writes against paths we actually
// own. The host's view of both /run/netns and /etc/netns is
// untouched; only this child sees the redirection.
//
// What needs which path:
//   - /run/netns/<name>     — `ip netns add` writes the bind-mount
//                             stub here (iproute2 hardcoded).
//   - /etc/netns/<name>/    — engine.writeResolvConf drops a
//                             per-netns resolv.conf here so
//                             `ip netns exec` mounts it inside
//                             the namespace at /etc/resolv.conf.
//
// Both target dirs must EXIST on the host as bind-mount targets
// (the install step creates them).
func setupNetnsDir() error {
	type shim struct{ src, dst, label string }
	shims := []shim{
		{
			src:   fmt.Sprintf("/tmp/veil-netns-%d", os.Getpid()),
			dst:   "/run/netns",
			label: "/run/netns",
		},
		{
			src:   fmt.Sprintf("/tmp/veil-etcnetns-%d", os.Getpid()),
			dst:   "/etc/netns",
			label: "/etc/netns",
		},
	}
	for _, s := range shims {
		if err := os.MkdirAll(s.src, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", s.src, err)
		}
		if _, err := os.Stat(s.dst); err != nil {
			return fmt.Errorf("%s missing on host — run: sudo veil setup --install-helpers (or: sudo mkdir -p /run/netns /etc/netns): %w", s.label, err)
		}
		if err := unix.Mount(s.src, s.dst, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s → %s: %w", s.src, s.dst, err)
		}
		// Mark shared so subsequent mount --bind from `ip netns`
		// (which sets propagation flags itself) doesn't fight us.
		if err := unix.Mount("", s.dst, "", unix.MS_SHARED, ""); err != nil {
			logger.L().Debug("userns child: MS_SHARED on "+s.label+" failed; iproute2 retries internally", "err", err)
		}
	}
	return nil
}
