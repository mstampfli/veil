package userns

import (
	"runtime"
	"testing"
)

func TestSupportLevelString(t *testing.T) {
	for _, tc := range []struct {
		in   SupportLevel
		want string
	}{
		{SupportNone, "none"},
		{SupportUserNet, "user+net"},
		{SupportFull, "user+net+time"},
	} {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("%v: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDetect runs the live probe. On Linux hosts that allow
// unprivileged user namespaces, this should return SupportUserNet
// or SupportFull. On Linux hosts where it's disabled (or non-Linux),
// SupportNone is correct. We only assert non-crash + sane string —
// the actual level is host-dependent.
func TestDetect(t *testing.T) {
	got := Detect()
	t.Logf("userns.Detect() = %v on %s/%s", got, runtime.GOOS, runtime.GOARCH)
	if got < SupportNone || got > SupportFull {
		t.Fatalf("unexpected level: %v", got)
	}
}
