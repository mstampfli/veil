package updater

import (
	"os"
	"testing"
)

// TestProFeedBase_Token verifies the per-buyer feed token is appended to the
// default feed URL, is slash-trimmed, and is overridden by VEIL_UPDATE_URL.
func TestProFeedBase_Token(t *testing.T) {
	oldTok := FeedToken
	oldEnv, hadEnv := os.LookupEnv("VEIL_UPDATE_URL")
	t.Cleanup(func() {
		FeedToken = oldTok
		if hadEnv {
			os.Setenv("VEIL_UPDATE_URL", oldEnv)
		} else {
			os.Unsetenv("VEIL_UPDATE_URL")
		}
	})
	os.Unsetenv("VEIL_UPDATE_URL")

	FeedToken = ""
	if got := proFeedBase(); got != DefaultProFeed {
		t.Fatalf("no token: got %q want %q", got, DefaultProFeed)
	}

	FeedToken = "abc123"
	if got, want := proFeedBase(), DefaultProFeed+"/abc123"; got != want {
		t.Fatalf("token: got %q want %q", got, want)
	}

	FeedToken = "/abc123/"
	if got, want := proFeedBase(), DefaultProFeed+"/abc123"; got != want {
		t.Fatalf("trimmed token: got %q want %q", got, want)
	}

	os.Setenv("VEIL_UPDATE_URL", "https://example.test/feed/")
	FeedToken = "ignored"
	if got, want := proFeedBase(), "https://example.test/feed"; got != want {
		t.Fatalf("env override should win: got %q want %q", got, want)
	}
}
