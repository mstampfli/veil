//go:build !linux

package userns

import (
	"errors"
	"os"
	"os/exec"
)

// Non-Linux stubs. The engine_*.go files import this package
// unconditionally so they can ask "is user-ns isolation available?"
// without sprinkling build tags through call sites. The answer on
// Windows / macOS / BSD is always "no — use the platform-native
// engine." Detect returns SupportNone.

func Detect() SupportLevel { return SupportNone }

func HandleProbeAndExit() bool { return false }

type SpawnConfig struct {
	Args          []string
	Env           []string
	Stdin         *os.File
	Stdout        *os.File
	Stderr        *os.File
	IncludeTimeNS bool
}

func Spawn(_ SpawnConfig) (*exec.Cmd, error) {
	return nil, errors.New("user namespaces are Linux-only")
}

func LevelFromEnv() SupportLevel { return SupportNone }

func CurrentPID() int { return os.Getpid() }

func getenv(k string) string { return os.Getenv(k) }
