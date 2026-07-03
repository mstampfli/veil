// Package inputjitter intercepts physical input events (keyboard, mouse)
// and replays them with randomized timing offsets so behavioral
// biometrics (keystroke dynamics, mouse-movement rhythm) can't
// fingerprint the user.
//
// Implementation strategy varies per platform:
//
//   - **Linux**: read events from /dev/input/event* with EVIOCGRAB
//     (exclusive access), forward to a /dev/uinput-created virtual
//     device with per-event random delay.
//
//   - **Windows** (future): SetWindowsHookEx WH_KEYBOARD_LL +
//     SendInput; intercept at the user-mode hook layer.
//
//   - **macOS** (future): CGEventTapCreate at session level + CGEventPost.
//
// All platforms expose the same Start/Stop API; non-Linux platforms
// currently return ErrNotSupported.
package inputjitter

import (
	"errors"
	"time"
)

// ErrNotSupported is returned by Start on platforms without a backend.
var ErrNotSupported = errors.New("input jitter not supported on this platform")

// Options configures the jitter daemon.
type Options struct {
	// MinDelay / MaxDelay bound the per-event delay range. The daemon
	// picks a uniform random delay in [MinDelay, MaxDelay] before
	// re-emitting each event. Recommended: 3ms-15ms (visible typing
	// remains responsive; defeats most keystroke-dynamics analyzers).
	MinDelay time.Duration
	MaxDelay time.Duration

	// JitterMouse: also intercept and jitter mouse events. Mouse jitter
	// is more visible to the user (cursor stutter); off by default.
	JitterMouse bool
}

// Jitter is a running input-jitter daemon. Stop releases the real
// devices and tears down the virtual ones.
type Jitter interface {
	Stop() error
}

// DefaultOptions returns conservative jitter defaults. Kept gentle on
// purpose: the daemon grabs the host's REAL keyboard and re-emits every
// event after this delay, so the range is felt as added input latency by
// the whole desktop. 1-6ms still perturbs inter-keystroke timing enough
// to degrade keystroke-dynamics classifiers (natural inter-key variance
// is ~10-30ms) while staying below the threshold most users notice.
func DefaultOptions() Options {
	return Options{
		MinDelay:    1 * time.Millisecond,
		MaxDelay:    6 * time.Millisecond,
		JitterMouse: false,
	}
}
