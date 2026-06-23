// Package logger provides a process-wide structured logger that writes
// to both stderr and a rotating file under the user's config dir.
//
// Usage:
//
//	logger.L().Info("starting profile", "name", p.Name)
//
// The first call to L() initializes the logger. Init() can also be called
// explicitly to control startup ordering. Log file path is exposed via
// LogPath() and TailFn() for the GUI logs view.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	// MaxLogBytes triggers rotation when the log file grows past this.
	MaxLogBytes = 5 * 1024 * 1024
	// KeepBackups is how many .N rotated files to retain.
	KeepBackups = 3
)

var (
	once     sync.Once
	logger   *slog.Logger
	logPath  string
	logMu    sync.Mutex // serializes rotation
	logFile  *os.File
	logLevel = new(slog.LevelVar) // dynamic level
)

// Init prepares the logger. Safe to call multiple times.
func Init() {
	once.Do(initOnce)
}

func initOnce() {
	logLevel.Set(slog.LevelInfo)
	if v := os.Getenv("VEIL_LOG_LEVEL"); v != "" {
		switch v {
		case "debug", "DEBUG":
			logLevel.Set(slog.LevelDebug)
		case "warn", "WARN":
			logLevel.Set(slog.LevelWarn)
		case "error", "ERROR":
			logLevel.Set(slog.LevelError)
		}
	}

	dir := defaultLogDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// Fall back to stderr-only.
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
		return
	}
	path := filepath.Join(dir, "veil.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
		return
	}
	logFile = f
	logPath = path

	replace := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.String("t", a.Value.Time().UTC().Format(time.RFC3339))
		}
		return a
	}
	// File handler logs everything at the active level. Stderr only
	// surfaces warnings and errors so CLI output stays clean.
	fileH := slog.NewTextHandler(&rotatingWriter{base: f, path: path}, &slog.HandlerOptions{
		Level:       logLevel,
		ReplaceAttr: replace,
	})
	stderrH := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:       slog.LevelWarn,
		ReplaceAttr: replace,
	})
	logger = slog.New(&teeHandler{a: fileH, b: stderrH}).With("pid", os.Getpid())
}

// teeHandler dispatches each record to two child handlers.
type teeHandler struct{ a, b slog.Handler }

func (t *teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return t.a.Enabled(ctx, l) || t.b.Enabled(ctx, l)
}
func (t *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	if t.a.Enabled(ctx, r.Level) {
		_ = t.a.Handle(ctx, r)
	}
	if t.b.Enabled(ctx, r.Level) {
		_ = t.b.Handle(ctx, r)
	}
	return nil
}
func (t *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &teeHandler{a: t.a.WithAttrs(attrs), b: t.b.WithAttrs(attrs)}
}
func (t *teeHandler) WithGroup(name string) slog.Handler {
	return &teeHandler{a: t.a.WithGroup(name), b: t.b.WithGroup(name)}
}

func defaultLogDir() string {
	// Under sudo/pkexec, write to the invoking user's config dir so the
	// CLI run as that same user (without sudo) finds the same log file.
	if os.Geteuid() == 0 {
		if home := invokingHome(); home != "" {
			return filepath.Join(home, ".config", "veil", "logs")
		}
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "/tmp/veil-logs"
	}
	return filepath.Join(cfg, "veil", "logs")
}

func invokingHome() string {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := osuser.Lookup(name); err == nil {
			return u.HomeDir
		}
	}
	if uid := os.Getenv("PKEXEC_UID"); uid != "" {
		if u, err := osuser.LookupId(uid); err == nil {
			return u.HomeDir
		}
	}
	return ""
}

// L returns the process logger.
func L() *slog.Logger {
	if logger == nil {
		Init()
	}
	return logger
}

// SetLevel changes the active log level.
func SetLevel(level slog.Level) {
	if logger == nil {
		Init()
	}
	logLevel.Set(level)
}

// LogPath returns the path of the current log file, or "" if not initialized.
func LogPath() string {
	if logger == nil {
		Init()
	}
	return logPath
}

// Tail returns up to maxLines bytes of the most recent log content.
func Tail(maxBytes int64) (string, error) {
	if logPath == "" {
		return "", fmt.Errorf("logger not initialized")
	}
	f, err := os.Open(logPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	off := st.Size() - maxBytes
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	// Drop a partial first line if we cut mid-line.
	if off > 0 {
		for i, c := range b {
			if c == '\n' {
				b = b[i+1:]
				break
			}
		}
	}
	return string(b), nil
}

// rotatingWriter rotates the underlying file on each write that crosses
// MaxLogBytes. It's intentionally simple: it serializes writes through a
// mutex.
type rotatingWriter struct {
	base *os.File
	path string
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	logMu.Lock()
	defer logMu.Unlock()
	if w.base == nil {
		return 0, fmt.Errorf("rotatingWriter: closed")
	}
	st, err := w.base.Stat()
	if err == nil && st.Size()+int64(len(p)) > MaxLogBytes {
		if err := rotate(w.base, w.path); err == nil {
			// Reopen the same path; the old file was renamed away.
			nf, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err == nil {
				_ = w.base.Close()
				w.base = nf
				logFile = nf
			}
		}
	}
	return w.base.Write(p)
}

func rotate(f *os.File, path string) error {
	for i := KeepBackups - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	if err := os.Rename(path, path+".1"); err != nil {
		return err
	}
	return nil
}

// WithCtx returns a logger annotated with values from ctx (placeholder for
// future tracing-id support).
func WithCtx(ctx context.Context) *slog.Logger {
	_ = ctx
	return L()
}

// Caller returns "file:line" of the caller — useful for one-off debug
// logs where adding source info inline is clearer than enabling AddSource
// globally.
func Caller(skip int) string {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s:%d", filepath.Base(file), line)
}
