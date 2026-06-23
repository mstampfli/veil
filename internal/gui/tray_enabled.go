//go:build tray

package gui

import (
	"context"
	"sync"
	"time"

	"github.com/getlantern/systray"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/mstampfli/veil/internal/logger"
)

// trayMu guards trayItems / trayCancel against concurrent rebuild.
var (
	trayMu     sync.Mutex
	trayItems  map[string]*systray.MenuItem
	trayCancel context.CancelFunc
)

// StartTray runs the system-tray loop in a separate goroutine. Called by
// the Wails main on startup. Tray menu shows a quick-launch entry per
// profile plus Show / Quit.
func (a *App) StartTray() {
	go systray.Run(func() { a.onTrayReady() }, nil)
}

func (a *App) onTrayReady() {
	systray.SetTitle("Veil")
	systray.SetTooltip("Veil — per-app tunnel isolation")
	systray.SetTemplateIcon(trayIcon, trayIcon)

	mShow := systray.AddMenuItem("Show window", "Bring the Veil window to front")
	systray.AddSeparator()

	// Profiles section is rebuilt every 5 seconds.
	a.rebuildTrayProfileList()
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit Veil", "Stop all profiles and exit")

	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			a.rebuildTrayProfileList()
		}
	}()

	for {
		select {
		case <-mShow.ClickedCh:
			if a.ctx != nil {
				wruntime.WindowShow(a.ctx)
				wruntime.WindowUnminimise(a.ctx)
			}
		case <-mQuit.ClickedCh:
			logger.L().Info("tray: quit")
			a.Shutdown(a.ctx)
			systray.Quit()
			return
		}
	}
}

// rebuildTrayProfileList tears down and re-creates the profile menu
// items. systray doesn't have a "remove menu item" API, so we hide
// items we don't need anymore.
func (a *App) rebuildTrayProfileList() {
	trayMu.Lock()
	defer trayMu.Unlock()
	if trayItems == nil {
		trayItems = map[string]*systray.MenuItem{}
	}
	if a.store == nil {
		return
	}
	profs, err := a.store.LoadAll()
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, p := range profs {
		seen[p.Name] = true
		item, ok := trayItems[p.Name]
		if !ok {
			item = systray.AddMenuItem(p.Name, "Click to launch / stop")
			trayItems[p.Name] = item
			go a.watchTrayItem(p.Name, item)
		}
		// Update title to reflect running state.
		a.mu.Lock()
		_, running := a.sessions[p.Name]
		a.mu.Unlock()
		if running {
			item.SetTitle("● " + p.Name)
		} else {
			item.SetTitle("○ " + p.Name)
		}
	}
	for name, item := range trayItems {
		if !seen[name] {
			item.Hide()
			delete(trayItems, name)
		}
	}
}

func (a *App) watchTrayItem(name string, item *systray.MenuItem) {
	for range item.ClickedCh {
		a.mu.Lock()
		_, running := a.sessions[name]
		a.mu.Unlock()
		if running {
			if err := a.StopProfile(name); err != nil {
				logger.L().Warn("tray stop", "profile", name, "err", err)
			}
		} else {
			if _, err := a.LaunchProfile(name); err != nil {
				logger.L().Warn("tray launch", "profile", name, "err", err)
			}
		}
	}
}

// trayIcon is a tiny placeholder PNG (16x16 dark purple square) so the
// tray has something visible. Real icon distribution is via packaging.
var trayIcon = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0xf3, 0xff, 0x61, 0x00, 0x00, 0x00,
	0x36, 0x49, 0x44, 0x41, 0x54, 0x38, 0x8d, 0x63, 0x60, 0xa0, 0x10, 0x30,
	0xa6, 0x82, 0x05, 0x10, 0x70, 0xff, 0xff, 0xff, 0xfc, 0x80, 0x29, 0x60,
	0x01, 0x04, 0xfc, 0xff, 0xff, 0xff, 0x3f, 0x60, 0x0a, 0x58, 0x00, 0x01,
	0xff, 0xff, 0xff, 0xff, 0x0f, 0x98, 0x02, 0x16, 0x40, 0xc0, 0x07, 0x00,
	0xa3, 0xae, 0x07, 0xa3, 0x36, 0xa1, 0x99, 0xa6, 0x00, 0x00, 0x00, 0x00,
	0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
}
