// Package updater implements veil's self-updater.
//
// The free (untagged) edition self-updates from public GitHub releases.
// The Pro edition can instead pull from a licensed feed when configured,
// authenticating with the installed license token, and refresh the local
// revocation list and (optionally) data packs from that feed.
//
// No network access is required to BUILD veil or to run any other command.
// Network calls happen only when the updater is explicitly invoked.
//
// Downloads are verified against a baked Ed25519 release public key
// (ReleasePubKey, set via -ldflags) before the running binary is replaced.
// A build with no release key refuses to apply updates.
package updater

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mstampfli/veil/internal/license"
)

// ReleasePubKey is the base64-encoded Ed25519 public key used to verify
// downloaded release assets, set at build time via -ldflags
// "-X github.com/mstampfli/veil/internal/updater.ReleasePubKey=<base64>".
// Empty means "no built-in release key": the updater will refuse to apply.
var ReleasePubKey = ""

// FeedToken is an optional per-buyer, unguessable path segment appended to the
// Pro update feed URL, baked into each buyer's build via -ldflags
// "-X github.com/mstampfli/veil/internal/updater.FeedToken=<token>".
// Each buyer's binary then pulls from <DefaultProFeed>/<token>/, a directory
// served only at that secret path. The token is not a secret the customer can
// be prevented from reading out of their own binary; its purpose is that a
// stranger cannot guess the URL, a leaked binary's update traffic is traceable
// to its token, and revoking a buyer is as simple as deleting their token
// directory from the feed. Empty (the free edition) uses the public path.
var FeedToken = ""

// GitHubRepo is the public repository the free edition pulls releases from.
const GitHubRepo = "mstampfli/veil"

// DefaultProFeed is the update feed base URL used when VEIL_UPDATE_URL is not
// set. Both editions read this feed's latest.json; the Pro edition adds the
// license bearer token (and refreshes the revocation list). Override per
// deployment with the VEIL_UPDATE_URL env var.
const DefaultProFeed = "https://updates.mstampfli.com/veil"

// userAgent identifies the updater to release hosts.
const userAgent = "veil-updater"

// Release describes a single downloadable update.
type Release struct {
	// Version is the release tag with any leading 'v' preserved as published
	// (e.g. "v1.4.0"). Use Newer / compare helpers for ordering.
	Version string
	// AssetURL is the download URL for the asset matching this host's
	// GOOS/GOARCH.
	AssetURL string
	// AssetName is the file name of the matched asset.
	AssetName string
	// SigURL is the download URL for the detached Ed25519 signature
	// (<asset>.sig). Empty if the host does not publish one separately, in
	// which case Apply derives it from AssetURL.
	SigURL string
	// Pro is true when this release came from the licensed Pro feed.
	Pro bool
}

// Options control how Apply behaves.
type Options struct {
	// Force allows replacing the running binary even when the candidate is
	// the same or an older version (a downgrade).
	Force bool
	// Progress, if non-nil, is called with (downloaded, total) byte counts
	// as the asset downloads. total may be 0 when unknown.
	Progress func(downloaded, total int64)
}

// httpClient is used for all network calls. A modest timeout keeps a hung
// mirror from wedging the command.
var httpClient = &http.Client{Timeout: 60 * time.Second}

// proActive reports whether this binary is the Pro edition AND a valid
// licence is installed, in which case the licensed feed is used.
func proActive() bool {
	return license.ProEdition() && license.LoadFromDefault().IsPro()
}

// licenseTokenPath returns the path of the installed license token.
func licenseTokenPath() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg, "veil", "license.jwt"), nil
}

// revokedPath returns the path of the local revocation list the Pro feed
// refreshes.
func revokedPath() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg, "veil", "revoked.txt"), nil
}

// proFeedBase returns the configured Pro feed base URL (env override, else
// the baked default), with any trailing slash trimmed.
func proFeedBase() string {
	if v := strings.TrimSpace(os.Getenv("VEIL_UPDATE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	base := strings.TrimRight(DefaultProFeed, "/")
	if t := strings.Trim(strings.TrimSpace(FeedToken), "/"); t != "" {
		base += "/" + t
	}
	return base
}

// archTokens lists the substrings that may identify this host's
// architecture in a published asset name (e.g. "amd64" or "x86_64").
func archTokens() []string {
	switch runtime.GOARCH {
	case "amd64":
		return []string{"amd64", "x86_64", "x64"}
	case "arm64":
		return []string{"arm64", "aarch64"}
	case "386":
		return []string{"386", "i386", "x86"}
	case "arm":
		return []string{"armv7", "armhf", "arm"}
	default:
		return []string{runtime.GOARCH}
	}
}

// assetMatchesHost reports whether an asset file name targets this host's
// GOOS/GOARCH. The name must contain the OS token and one arch token.
func assetMatchesHost(name string) bool {
	n := strings.ToLower(name)
	osTok := runtime.GOOS
	if runtime.GOOS == "darwin" {
		// Some publishers label macOS assets "macos" or "osx".
		if !strings.Contains(n, "darwin") && !strings.Contains(n, "macos") && !strings.Contains(n, "osx") {
			return false
		}
	} else if !strings.Contains(n, osTok) {
		return false
	}
	for _, a := range archTokens() {
		if strings.Contains(n, a) {
			return true
		}
	}
	return false
}

// CheckLatest queries the self-hosted update feed (latest.json) and returns the
// newest release with an asset matching this host. The Pro edition authenticates
// with its license; the free edition reads the feed anonymously. It does not
// download or apply anything. checkLatestGitHub remains available as an
// alternate source but is not used by default.
func CheckLatest(ctx context.Context) (Release, error) {
	return checkLatestPro(ctx)
}

// ---- GitHub (free edition) ---------------------------------------------

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

func checkLatestGitHub(ctx context.Context) (Release, error) {
	url := "https://api.github.com/repos/" + GitHubRepo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("contacting GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("GitHub returned %s", resp.Status)
	}

	var gr ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&gr); err != nil {
		return Release{}, fmt.Errorf("parsing GitHub response: %w", err)
	}
	if gr.TagName == "" {
		return Release{}, errors.New("no release tag found")
	}

	rel := Release{Version: gr.TagName}
	// Match the binary asset and a detached .sig if published.
	sigByBase := map[string]string{}
	for _, a := range gr.Assets {
		if strings.HasSuffix(strings.ToLower(a.Name), ".sig") {
			base := strings.TrimSuffix(a.Name, filepath.Ext(a.Name))
			sigByBase[base] = a.BrowserDownloadURL
		}
	}
	for _, a := range gr.Assets {
		if strings.HasSuffix(strings.ToLower(a.Name), ".sig") {
			continue
		}
		if assetMatchesHost(a.Name) {
			rel.AssetURL = a.BrowserDownloadURL
			rel.AssetName = a.Name
			if sig, ok := sigByBase[a.Name]; ok {
				rel.SigURL = sig
			}
			break
		}
	}
	if rel.AssetURL == "" {
		return Release{}, fmt.Errorf("no asset for %s/%s in release %s", runtime.GOOS, runtime.GOARCH, gr.TagName)
	}
	return rel, nil
}

// ---- Pro licensed feed --------------------------------------------------

// proManifest is the JSON the licensed feed serves at <base>/latest.json.
type proManifest struct {
	Version string `json:"version"`
	// Assets maps "<goos>/<goarch>" to a relative or absolute asset path.
	Assets map[string]string `json:"assets"`
}

// authHeader reads the installed license token and returns a Bearer value.
func authHeader() (string, error) {
	p, err := licenseTokenPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("reading license token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("license token is empty")
	}
	return "Bearer " + tok, nil
}

// resolveFeedURL turns a possibly-relative manifest path into an absolute
// URL under the feed base.
func resolveFeedURL(base, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return base + "/" + strings.TrimLeft(path, "/")
}

func checkLatestPro(ctx context.Context) (Release, error) {
	base := proFeedBase()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest.json", nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	// The Pro edition authenticates with its license so the feed can serve
	// (and account for) Pro builds; the free edition reads the feed anonymously.
	if proActive() {
		if auth, err := authHeader(); err == nil {
			req.Header.Set("Authorization", auth)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("contacting update feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("update feed returned %s", resp.Status)
	}

	var m proManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&m); err != nil {
		return Release{}, fmt.Errorf("parsing update manifest: %w", err)
	}
	if m.Version == "" {
		return Release{}, errors.New("update manifest has no version")
	}
	key := runtime.GOOS + "/" + runtime.GOARCH
	asset, ok := m.Assets[key]
	if !ok || asset == "" {
		return Release{}, fmt.Errorf("no asset for %s in update manifest", key)
	}
	assetURL := resolveFeedURL(base, asset)
	return Release{
		Version:   m.Version,
		AssetURL:  assetURL,
		AssetName: filepath.Base(assetURL),
		SigURL:    assetURL + ".sig",
		Pro:       true,
	}, nil
}

// RefreshRevocations pulls the Pro feed's revoked.txt and writes it to
// ~/.config/veil/revoked.txt. It is a no-op (returning nil) for the free
// edition since the public feed has no licensed revocation list. Offline-
// friendly: callers may ignore the error.
func RefreshRevocations(ctx context.Context) error {
	if !proActive() {
		return nil
	}
	base := proFeedBase()
	auth, err := authHeader()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/revoked.txt", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Authorization", auth)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching revocation list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil // feed publishes none; nothing to revoke
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation feed returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	dst, err := revokedPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dst, body, 0o600)
}

// ---- version comparison -------------------------------------------------

// normalizeVersion strips a leading 'v' and any pre-release / build suffix
// after the first '-' or '+', returning the dotted numeric core.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	return v
}

// compareVersions returns -1 if a < b, 0 if equal, +1 if a > b using a small
// semver-ish dotted-numeric comparison. The literal "dev" sorts below any
// real version; two "dev" values are equal.
func compareVersions(a, b string) int {
	an, bn := normalizeVersion(a), normalizeVersion(b)
	aDev := an == "" || strings.EqualFold(a, "dev")
	bDev := bn == "" || strings.EqualFold(b, "dev")
	switch {
	case aDev && bDev:
		return 0
	case aDev:
		return -1
	case bDev:
		return 1
	}
	af := strings.Split(an, ".")
	bf := strings.Split(bn, ".")
	n := len(af)
	if len(bf) > n {
		n = len(bf)
	}
	for i := 0; i < n; i++ {
		ai, bi := 0, 0
		if i < len(af) {
			ai, _ = strconv.Atoi(af[i])
		}
		if i < len(bf) {
			bi, _ = strconv.Atoi(bf[i])
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

// Newer reports whether remote is a strictly newer version than local.
func Newer(remote, local string) bool {
	return compareVersions(remote, local) > 0
}

// ---- apply --------------------------------------------------------------

// Apply downloads rel's asset next to the running executable, verifies its
// Ed25519 signature against the baked release public key, then atomically
// replaces the running binary. It refuses to downgrade unless opts.Force.
//
// Replacement strategy (Linux/macOS and Windows alike): rename the current
// executable to <exe>.old, move the verified new file into place, chmod
// 0755, then best-effort remove the .old. On Windows a running .exe cannot
// be overwritten in place but it CAN be renamed, so this "rename self, then
// move the new file in" dance is what makes in-place replacement work; the
// .old copy is removed on the next run if it is still locked now.
func Apply(ctx context.Context, rel Release, opts Options) error {
	if ReleasePubKey == "" {
		return errors.New("this build has no release public key baked in; refusing to self-update (rebuild with -ldflags -X .../internal/updater.ReleasePubKey=<base64>)")
	}
	pub, err := decodePubKey(ReleasePubKey)
	if err != nil {
		return err
	}

	if !opts.Force && compareVersions(rel.Version, currentVersion()) <= 0 {
		return fmt.Errorf("candidate %s is not newer than current %s (use --force to override)", rel.Version, currentVersion())
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)

	// Download the asset to a temp file next to the executable so the final
	// rename stays on the same filesystem (atomic).
	tmp, err := os.CreateTemp(dir, ".veil-update-*")
	if err != nil {
		return fmt.Errorf("creating temp file (need write access to %s): %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := download(ctx, rel, tmp, opts.Progress); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Verify signature over the downloaded bytes.
	data, err := os.ReadFile(tmpName)
	if err != nil {
		return err
	}
	sig, err := fetchSignature(ctx, rel)
	if err != nil {
		return fmt.Errorf("fetching signature: %w", err)
	}
	if !ed25519.Verify(pub, data, sig) {
		return errors.New("signature verification FAILED; refusing to install (download may be corrupt or tampered)")
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}

	// Atomic replace: move current exe aside, move new into place.
	old := exe + ".old"
	_ = os.Remove(old) // clear any leftover from a previous run
	if err := os.Rename(exe, old); err != nil {
		return fmt.Errorf("renaming current binary aside: %w", err)
	}
	if err := os.Rename(tmpName, exe); err != nil {
		// Roll back the rename so the user is not left without a binary.
		_ = os.Rename(old, exe)
		return fmt.Errorf("moving new binary into place: %w", err)
	}
	cleanup = false // tmp is now the live binary

	if err := os.Chmod(exe, 0o755); err != nil {
		// Non-fatal: the file is installed; just report.
		return fmt.Errorf("installed but chmod failed: %w", err)
	}
	_ = os.Remove(old) // best effort; on Windows it may still be locked
	return nil
}

// currentVersion returns the running binary's version, read from the cli
// package's build-time variable via the bridge in version.go to avoid an
// import cycle. It is wired by SetCurrentVersion at init.
func currentVersion() string {
	if curVersion != "" {
		return curVersion
	}
	return "dev"
}

var curVersion string

// SetCurrentVersion records the running binary's version so Apply's
// downgrade guard and CheckLatest callers agree on "current". The cli
// package calls this; keeping it here avoids importing cli (cycle).
func SetCurrentVersion(v string) { curVersion = v }

func decodePubKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("release key not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release key wrong length: got %d want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// download streams rel's asset into w, reporting progress if provided.
func download(ctx context.Context, rel Release, w io.Writer, progress func(downloaded, total int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.AssetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	if rel.Pro {
		if auth, err := authHeader(); err == nil {
			req.Header.Set("Authorization", auth)
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %s", resp.Status)
	}
	total := resp.ContentLength
	var done int64
	buf := make([]byte, 64*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			done += int64(n)
			if progress != nil {
				progress(done, total)
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// fetchSignature downloads the detached signature for rel and decodes it to
// the raw 64-byte Ed25519 signature. The signature file may be raw 64 bytes
// or base64-encoded.
func fetchSignature(ctx context.Context, rel Release) ([]byte, error) {
	sigURL := rel.SigURL
	if sigURL == "" {
		sigURL = rel.AssetURL + ".sig"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sigURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if rel.Pro {
		if auth, err := authHeader(); err == nil {
			req.Header.Set("Authorization", auth)
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signature returned %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	return parseSignature(raw)
}

// parseSignature accepts either a raw 64-byte signature or a base64-encoded
// one (with optional surrounding whitespace) and returns the 64 raw bytes.
func parseSignature(raw []byte) ([]byte, error) {
	if len(raw) == ed25519.SignatureSize {
		return raw, nil
	}
	s := strings.TrimSpace(string(raw))
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := dec.DecodeString(s); err == nil && len(b) == ed25519.SignatureSize {
			return b, nil
		}
	}
	return nil, fmt.Errorf("signature is neither raw 64 bytes nor base64 of 64 bytes (got %d bytes)", len(raw))
}
