//go:build linux

package gui

// User-accessible shutdown channel.
//
// veil-gui runs as root (it has to — netns / iptables / nftables ops
// need it). Once elevated, the normal user CAN'T pkill the process:
// Unix permissions block kill(2) across UID boundaries. The window
// close button SHOULD fire Wails OnShutdown → app.Shutdown, but on
// some webkit2gtk setups the close event doesn't propagate cleanly
// when the process is uid 0 talking to a uid 1000 X server.
//
// Solution: open a Unix domain socket, chown it to the launching user
// (SUDO_UID / PKEXEC_UID), and treat ANY connection on it as "please
// shut down." A small `veil quit` CLI then connects + closes; the
// daemon catches that, runs Shutdown(), exits cleanly. No password
// prompt, no pkill -9 dance.

import (
	"context"
	"net"
	"os"
	"strconv"

	"github.com/mstampfli/veil/internal/logger"
)

// ShutdownSocketPath is the well-known location both ends agree on.
const ShutdownSocketPath = "/tmp/veil-gui.sock"

// StartShutdownSocket opens the Unix socket and spawns a goroutine
// that watches for connections. The first connection triggers
// app.Shutdown + process exit. Subsequent calls are no-ops.
//
// Best-effort: failure to bind (already in use, permissions) is
// logged but doesn't abort startup. If two veil-gui instances race
// for the socket the second will fail; the first wins as the
// shutdown owner.
func (a *App) StartShutdownSocket() {
	// Remove stale socket from a previous crashed run.
	_ = os.Remove(ShutdownSocketPath)

	l, err := net.Listen("unix", ShutdownSocketPath)
	if err != nil {
		logger.L().Warn("shutdown socket: bind failed; window-close + sudo kill remain the only ways to stop", "err", err)
		return
	}

	// Chown to the user that ran sudo/pkexec so they can write to
	// the socket from a normal-user shell. Falls back to 0666 mode
	// if we can't determine the launching uid.
	if !chownToLaunchingUser(ShutdownSocketPath) {
		_ = os.Chmod(ShutdownSocketPath, 0o666)
		logger.L().Warn("shutdown socket: couldn't determine launching uid; using world-writable mode")
	} else {
		_ = os.Chmod(ShutdownSocketPath, 0o660)
	}

	logger.L().Info("shutdown socket ready", "path", ShutdownSocketPath)

	go func() {
		defer l.Close()
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
		logger.L().Info("shutdown socket: connection received — initiating shutdown")
		a.Shutdown(context.Background())
		// Remove the socket file so a subsequent veil-gui start
		// doesn't see a stale entry.
		_ = os.Remove(ShutdownSocketPath)
		// Hard exit. Wails' OnShutdown won't fire from here, but
		// app.Shutdown above already tore down sessions, which is
		// what the OnShutdown hook was going to do anyway.
		os.Exit(0)
	}()
}

// removeShutdownSocketIfPresent unlinks the socket file. Idempotent.
// Used by RequestShutdown's exit path so a stale entry doesn't
// confuse the next launch's bind.
func removeShutdownSocketIfPresent() error {
	if _, err := os.Stat(ShutdownSocketPath); err == nil {
		return os.Remove(ShutdownSocketPath)
	}
	return nil
}

// chownToLaunchingUser tries SUDO_UID then PKEXEC_UID env vars to
// find the original-user UID, then chowns the path to them. Returns
// true on success.
func chownToLaunchingUser(path string) bool {
	for _, v := range []string{"SUDO_UID", "PKEXEC_UID"} {
		if s := os.Getenv(v); s != "" {
			if uid, err := strconv.Atoi(s); err == nil && uid > 0 {
				gid := uid
				if g := os.Getenv("SUDO_GID"); g != "" {
					if n, err := strconv.Atoi(g); err == nil && n > 0 {
						gid = n
					}
				}
				if err := os.Chown(path, uid, gid); err == nil {
					return true
				}
			}
		}
	}
	return false
}
