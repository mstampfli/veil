// veil-gui — Wails-powered desktop GUI for Veil.
package main

import (
	"context"
	"embed"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/mstampfli/veil/internal/backends/all"
	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/gui"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/osutil"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:dist
var assets embed.FS

func main() {
	// .desktop launchers and many display managers ship a stripped
	// PATH that excludes /sbin and /usr/sbin. Veil shells out to ip
	// and iptables which live there, so they'd fail with "command
	// not found" before our own logic ever runs. Fix it once at the
	// top of main and forget about it.
	osutil.EnsureSysPath()
	// iptables-nft writes need a writable lock file path; default
	// /run/xtables.lock is root-only.
	osutil.EnsureIPTablesLock()
	// If the user is in /etc/group's veil group but the current
	// session was started before that (no veil in supplementary
	// gids), re-exec under `sg veil` so /dev/net/tun is openable
	// without forcing a desktop logout. Pure no-op when already
	// in veil, or when sg / veil group / membership is missing.
	// MUST run before MaybeRunUsernsChild — child entry inherits
	// our group set; we want it to inherit veil-included.
	osutil.EnsureVeilGroup()

	// User-ns child entrypoint. When veil-gui is re-execed by its
	// own parent process inside a CLONE_NEWUSER + CLONE_NEWNET stack
	// (the new privilege-minimization path), VEIL_USERNS_CHILD is
	// set and we route into the child-mode engine helper instead of
	// starting the GUI runtime. Falls through silently when running
	// normally so the standard GUI launch path is unchanged.
	engine.MaybeRunUsernsChild()

	// /run is tmpfs and gets wiped on every reboot, so /run/netns
	// disappears between sessions. Reinstate it (and drop a
	// tmpfiles.d entry so systemd recreates it automatically on
	// future boots) before we ever spawn a user-ns child that
	// would otherwise fail with "/run/netns missing on host".
	// MUST run AFTER MaybeRunUsernsChild — otherwise the child
	// (which can't pkexec from inside a user-ns) would try too.
	osutil.EnsureNetnsRuntimeDir()

	logger.Init()
	engine.InstallCrashGuard()
	// Clear out any veil userns children orphaned by a previous gui
	// crash (PPID=1, /dev/input/event* still grabbed). Without this
	// every relaunch fails with EVIOCGRAB busy + the user has no way
	// short of reboot to get unstuck. Best-effort; logs WARN per kill.
	engine.ReapOrphanUsernsChildren()
	logger.L().Info("veil-gui starting")
	app := gui.NewApp()

	// Signal handler: when the process gets SIGINT/SIGTERM/SIGHUP from
	// a task manager, kill, or terminal, tear down all active profile
	// sessions before the runtime exits. Without this, network
	// namespaces and veth pairs leak — the next launch would error
	// with "veth add: file exists" or similar.
	//
	// Wails' OnShutdown only fires for graceful UI close (window-X);
	// it doesn't run on signal-induced exit. We add our own handler.
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	go func() {
		<-ctx.Done()
		logger.L().Info("veil-gui: signal received, shutting down sessions")
		app.Shutdown(context.Background())
		os.Exit(0)
	}()

	err := wails.Run(&options.App{
		Title:  "Veil",
		Width:  1100,
		Height: 720,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 7, G: 9, B: 13, A: 1},
		OnStartup: func(ctx context.Context) {
			app.Startup(ctx)
			app.StartTray()
			// Open the user-accessible shutdown socket so a normal
			// user (the one who ran pkexec/sudo) can stop the GUI
			// without needing root again. Linux-only; no-op stub
			// elsewhere.
			app.StartShutdownSocket()
		},
		OnShutdown: func(ctx context.Context) {
			app.Shutdown(ctx)
		},
		Bind: []any{app},
	})
	if err != nil {
		log.Fatal(err)
	}
}
