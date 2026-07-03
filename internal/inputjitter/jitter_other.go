//go:build !linux

package inputjitter

// Start is a no-op on non-Linux platforms (for now).
//
// To extend:
//   - Windows: use SetWindowsHookEx with WH_KEYBOARD_LL, intercept
//     WM_KEYDOWN/WM_KEYUP, post via SendInput after a randomized delay.
//   - macOS: use CGEventTapCreate at the kCGSessionEventTap level,
//     intercept CGEventTypeKeyDown/Up, repost via CGEventPost.
func Start(opts Options) (Jitter, error) {
	return nil, ErrNotSupported
}

// StartMouse is a no-op on non-Linux platforms.
func StartMouse(opts Options) (Jitter, error) {
	return nil, ErrNotSupported
}
