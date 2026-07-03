//go:build !tray

package gui

// StartTray is a no-op when the binary is built without the `tray` tag.
// To enable: `go build -tags "desktop production webkit2_41 tray" ...`
// (requires libayatana-appindicator3-dev on Linux).
func (a *App) StartTray() {}
