package cli

// `veil setup --install-geoip` downloads DB-IP's free Country + ASN
// databases (CC-BY-4.0, no signup required) and places them at the
// user-config dir locations Veil's geoip package looks for. After
// running, the GUI dashboard's country/ASN/map columns populate, and
// drift checks gain country verification.
//
// We use DB-IP's "lite" free tier — same MaxMind .mmdb format as
// GeoLite2, fully compatible with our github.com/oschwald/maxminddb-
// golang reader. Updated monthly. URL pattern:
//   https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz
//   https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.mmdb.gz
//
// We try the current month first, falling back month-by-month for up
// to 3 months if 404 (DB-IP's free tier sometimes lags by a month).

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mstampfli/veil/internal/geoip"
	"github.com/mstampfli/veil/internal/profile"
)

// GeoIPStaleAfter is how old the local GeoIP data may be before veil
// considers it stale and worth refreshing/warning about. DB-IP's free
// tier republishes monthly, so ~5 weeks gives margin for the new month
// to actually publish before we start nagging.
const GeoIPStaleAfter = 35 * 24 * time.Hour

func runInstallGeoIP() error {
	dir, err := geoipInstallDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	type job struct {
		urlPath string
		dest    string
	}
	jobs := []job{
		{urlPath: "country-lite", dest: filepath.Join(dir, "geoip-country.mmdb")},
		{urlPath: "asn-lite", dest: filepath.Join(dir, "geoip-asn.mmdb")},
	}
	for _, j := range jobs {
		fmt.Printf("downloading %s …\n", filepath.Base(j.dest))
		if err := downloadDBIP(j.urlPath, j.dest); err != nil {
			return fmt.Errorf("%s: %w", j.urlPath, err)
		}
		// World-readable so any user (the unprivileged GUI process)
		// can read system-wide installs without permission games.
		_ = os.Chmod(j.dest, 0o644)
		// Verify the file actually exists at the dest, not just
		// "download claimed success". Past UX bug: rename failures
		// were swallowed, install reported ✓, file wasn't there.
		if st, err := os.Stat(j.dest); err != nil || st.Size() < 1024 {
			return fmt.Errorf("post-write verify failed for %s: %w (size=%d)",
				j.dest, err, fileSizeOrZero(st))
		}
		fmt.Printf("  ✓ %s\n", j.dest)
	}
	fmt.Println()
	fmt.Println("GeoIP databases installed. Restart veil-gui (or run a fresh probe) to pick them up.")
	fmt.Println("Verify with:")
	fmt.Println("    ls -la " + dir + "/geoip-*.mmdb")
	return nil
}

func fileSizeOrZero(fi os.FileInfo) int64 {
	if fi == nil {
		return 0
	}
	return fi.Size()
}

// RefreshGeoIPIfStale re-downloads the DB-IP country + ASN databases into
// the per-user (or system) install dir IF the currently-installed country
// DB is missing or its file is older than maxAge. Returns (refreshed,
// err).
//
// Best-effort by contract: a download failure (offline, db-ip 404/down)
// returns a non-nil err but is NOT fatal — callers log and keep using the
// existing (stale) DB. Returns (false, nil) when the DB is already fresh.
//
// PRIVACY: the fetch goes to download.db-ip.com from the HOST's real IP
// (it runs in the parent process, before any tunnel exists). It only
// reveals "this IP downloaded the free GeoIP DB", but it IS a real-IP
// network call — callers must gate it behind explicit opt-in and never
// block startup on it.
func RefreshGeoIPIfStale(maxAge time.Duration) (bool, error) {
	dir, err := geoipInstallDir()
	if err != nil {
		return false, err
	}
	country := filepath.Join(dir, "geoip-country.mmdb")
	if fresh, _ := fileYoungerThan(country, maxAge); fresh {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	jobs := []struct{ urlPath, dest string }{
		{"country-lite", country},
		{"asn-lite", filepath.Join(dir, "geoip-asn.mmdb")},
	}
	var firstErr error
	for _, j := range jobs {
		if err := downloadDBIP(j.urlPath, j.dest); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		_ = os.Chmod(j.dest, 0o644)
	}
	if firstErr != nil {
		return false, firstErr
	}
	return true, nil
}

// fileYoungerThan reports whether path exists and its mtime is within
// maxAge of now. A missing/unstat-able file returns (false, err) so the
// caller treats it as "needs refresh".
func fileYoungerThan(path string, maxAge time.Duration) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return time.Since(fi.ModTime()) < maxAge, nil
}

// profileReliesOnLocalGeoIP reports whether the profile's verification
// path consults the local GeoIP DB to label/verify the exit — i.e. any
// lock dim, an explicit require_exit_country, or a per-hop Tor exit
// country pin. Profiles that don't are never nagged about staleness.
func profileReliesOnLocalGeoIP(p *profile.Profile) bool {
	if p.AnyLockEnabled() || strings.TrimSpace(p.RequireExitCountry) != "" {
		return true
	}
	for _, b := range p.Chain {
		if strings.TrimSpace(b.TorExitCountry) != "" {
			return true
		}
	}
	return false
}

// geoStalenessWarning returns the fail-closed warning to print (or "" for
// none), given the loaded country DB's build time. Pure so it's unit
// testable. A DB older than GeoIPStaleAfter warns; a missing DB warns it
// can't verify; a fresh DB is silent.
func geoStalenessWarning(buildTime time.Time, haveBuildTime, available bool, now time.Time) string {
	if haveBuildTime {
		if age := now.Sub(buildTime); age > GeoIPStaleAfter {
			return fmt.Sprintf("[veil] warning: GeoIP country DB built %s (%d days old). "+
				"lock_country/lock_asn verify the live exit against this offline DB, so address reassignments since then "+
				"can cause a false mismatch (blocked launch) or a false pass. "+
				"Refresh: `veil setup --install-geoip` (or set VEIL_GEOIP_AUTO_REFRESH=1).",
				buildTime.Format("2006-01-02"), int(age.Hours()/24))
		}
		return ""
	}
	if !available {
		return "[veil] warning: no GeoIP database installed — lock_country/lock_asn cannot verify the exit. Install: `veil setup --install-geoip`."
	}
	return ""
}

// geoPreflight is a fail-closed pre-flight check on the local GeoIP DB,
// run from the parent `veil run`/`shell` process BEFORE the chain comes
// up. It only does anything for profiles that actually rely on the local
// DB for verification (any lock dim, require_exit_country, or a Tor exit
// country pin) — profiles that don't care about geo are never nagged.
//
// Two independent actions, both non-fatal:
//
//   - Always: a ZERO-NETWORK staleness warning. lock_country / lock_asn
//     compare the live exit against this offline DB and audit.Crash on a
//     mismatch, so a stale DB can wrongly block a fine launch (or pass a
//     bad one). We surface the build date so the user can judge.
//
//   - Opt-in only (VEIL_GEOIP_AUTO_REFRESH=1): a best-effort background
//     refresh. It runs in a goroutine so it NEVER blocks startup (the
//     download has a multi-minute timeout); the fresh DB applies on the
//     next launch. Off by default because it fetches from the user's REAL
//     IP (see RefreshGeoIPIfStale privacy note).
func geoPreflight(p *profile.Profile) {
	if !profileReliesOnLocalGeoIP(p) {
		return
	}

	bt, ok := geoip.CountryDBBuildTime()
	if w := geoStalenessWarning(bt, ok, geoip.IsAvailable(), time.Now()); w != "" {
		fmt.Fprintln(os.Stderr, w)
	}

	if os.Getenv("VEIL_GEOIP_AUTO_REFRESH") == "1" {
		fmt.Fprintln(os.Stderr, "[veil] VEIL_GEOIP_AUTO_REFRESH=1: refreshing GeoIP DB in background (fetches db-ip.com from your REAL IP)...")
		go func() {
			refreshed, err := RefreshGeoIPIfStale(GeoIPStaleAfter)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[veil] GeoIP auto-refresh failed (keeping existing DB): %v\n", err)
			} else if refreshed {
				fmt.Fprintln(os.Stderr, "[veil] GeoIP DB refreshed (applies on next launch).")
			}
		}()
	}
}

// geoipInstallDir picks the install location based on privilege:
//
//   - Running as root (sudo / pkexec)   → /usr/local/share/veil/
//     System-wide path. Persists across reboots, readable by every
//     local user. The Veil geoip package's search list includes this
//     path, so any user (and the unprivileged GUI) finds the DB.
//
//   - Running as the user (no elevation) → <user>/.config/veil/
//     Per-user path. Same path the geoip package searches first.
//
// Old bug this replaces: the function always returned the launching
// user's ~/.config/veil — but failed to resolve that user's home
// when the elevation came via pkexec (only SUDO_USER was honored,
// not PKEXEC_UID). With pkexec you ended up writing to /root/.config
// which the GUI process can't read. Hence "downloaded it 10 times,
// it never persists" — it persisted in root's home.
func geoipInstallDir() (string, error) {
	if os.Geteuid() == 0 {
		return "/usr/local/share/veil", nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg, "veil"), nil
}

// downloadDBIP fetches the current month's DB-IP lite mmdb (gzip),
// decompresses, and writes to dest atomically. Falls back month-by-
// month for up to 3 months when the current month isn't published yet.
func downloadDBIP(urlPath, dest string) error {
	now := time.Now().UTC()
	var lastErr error
	for i := 0; i < 3; i++ {
		t := now.AddDate(0, -i, 0)
		ym := fmt.Sprintf("%d-%02d", t.Year(), int(t.Month()))
		url := fmt.Sprintf("https://download.db-ip.com/free/dbip-%s-%s.mmdb.gz", urlPath, ym)
		err := tryDownloadAndExtract(url, dest)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

func tryDownloadAndExtract(url, dest string) error {
	cli := &http.Client{Timeout: 5 * time.Minute}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "veil-setup/"+Version+" (+https://github.com/mstampfli/veil)")
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, url)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()

	tmp := dest + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 10)
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, gz); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func chownToLaunchingUser(path string) {
	uidS := os.Getenv("SUDO_UID")
	gidS := os.Getenv("SUDO_GID")
	if uidS == "" {
		uidS = os.Getenv("PKEXEC_UID")
		gidS = uidS
	}
	if uidS == "" {
		return
	}
	uid, err1 := strconv.Atoi(uidS)
	gid, _ := strconv.Atoi(gidS)
	if err1 != nil {
		return
	}
	if gid == 0 {
		gid = uid
	}
	_ = os.Chown(path, uid, gid)
}

// userConfigDir returns the user's veil config dir, honoring SUDO_USER
// when running elevated so we don't accidentally install into root's
// home.
func userConfigDir() (string, error) {
	// If sudo'd, prefer the launching user's home so the GUI (running
	// non-root or as the user via pkexec) can find the DB.
	if home := launchingUserHome(); home != "" {
		return filepath.Join(home, ".config", "veil"), nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg, "veil"), nil
}

func launchingUserHome() string {
	if user := os.Getenv("SUDO_USER"); user != "" {
		// Use getent-style lookup via /etc/passwd.
		if home := homeForUser(user); home != "" {
			return home
		}
	}
	return ""
}

func homeForUser(name string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	for _, line := range splitLines(string(data)) {
		fields := splitColons(line)
		if len(fields) >= 6 && fields[0] == name {
			return fields[5]
		}
	}
	return ""
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func splitColons(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
