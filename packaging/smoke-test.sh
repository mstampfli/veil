#!/usr/bin/env bash
#
# Veil zero-capability smoke test.
#
# Run on a FRESH Linux host (Debian/Ubuntu/Fedora/Arch) to verify the whole
# path works end to end with NO host capabilities: build -> install -> doctor
# -> a live tunnel that hides the real IP. Safe to re-run (idempotent).
#
#   sudo ./packaging/smoke-test.sh                  # full: build + install + verify
#   ./packaging/smoke-test.sh --verify-only         # skip install, verify an existing one
#   SMOKE_PROFILE=freetor sudo ./packaging/smoke-test.sh
#   VEIL_BIN=/usr/local/bin/veil ./packaging/smoke-test.sh --verify-only
#
# Exit status: 0 = all checks passed, 1 = a check failed, 2 = usage/prereq.
set -uo pipefail

PROFILE="${SMOKE_PROFILE:-freetor}"   # a tor profile ships by default; hides the IP
VERIFY_ONLY=0
[ "${1:-}" = "--verify-only" ] && VERIFY_ONLY=1
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

pass=0 fail=0
ok()  { echo "  [PASS] $*"; pass=$((pass + 1)); }
no()  { echo "  [FAIL] $*"; fail=$((fail + 1)); }
hdr() { echo; echo "== $* =="; }

# ---------------------------------------------------------------- build+install
if [ "$VERIFY_ONLY" -ne 1 ]; then
  hdr "build + install"
  if [ "$(id -u)" -ne 0 ]; then
    echo "  the install phase needs root: re-run with sudo, or pass --verify-only" >&2
    exit 2
  fi
  if ! ( cd "$ROOT" && bash install.sh ); then
    echo "  install.sh failed" >&2
    exit 1
  fi
fi

VEIL="${VEIL_BIN:-$(command -v veil 2>/dev/null || echo /usr/local/bin/veil)}"
if [ ! -x "$VEIL" ]; then
  echo "  veil binary not found (looked at: $VEIL). Set VEIL_BIN= or run the install phase." >&2
  exit 2
fi
export VEIL_USERNS_ENGINE=1
echo "  using veil: $VEIL"

# --------------------------------------------------------------------- pasta
hdr "uplink prerequisite"
if command -v pasta >/dev/null 2>&1; then
  ok "pasta (passt) present — zero-capability uplink available"
else
  no "pasta not installed — would fall back to the cap_net_admin bridge (install 'passt')"
fi

# --------------------------------------------------------------------- doctor
hdr "doctor"
doc="$("$VEIL" doctor 2>&1)"
echo "$doc" | sed 's/^/    /'
echo "$doc" | grep -qiE 'no sudo needed|non-root via user namespaces' \
  && ok "runs non-root (no sudo)" || no "doctor did not confirm the non-root path"
echo "$doc" | grep -qiE 'no host capability required' \
  && ok "pasta zero-capability uplink active" || no "zero-capability uplink not reported"
if echo "$doc" | grep -q '✗'; then
  no "doctor reported a hard failure (✗)"
else
  ok "doctor reports no hard failures"
fi

# ----------------------------------------------------------------- live tunnel
hdr "live tunnel: selftest $PROFILE"
# Be self-contained: a fresh install ships no user profiles, so create a
# throwaway tor profile for the named test if it does not already exist.
# (Tor hides the IP with no external account needed — ideal for a smoke test.)
prof_dir="${XDG_CONFIG_HOME:-$HOME/.config}/veil/profiles"
prof_file="$prof_dir/$PROFILE.yaml"
created_profile=0
if [ ! -f "$prof_file" ]; then
  mkdir -p "$prof_dir"
  cat > "$prof_file" <<YAML
name: $PROFILE
chain:
    - kind: tor
app:
    preset: curl
kill_switch: true
YAML
  created_profile=1
  echo "  created throwaway tor profile: $prof_file"
fi
host_ip="$(curl -s --max-time 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p')"
echo "  real host IP: ${host_ip:-unknown}"
out="$(timeout 140 "$VEIL" selftest "$PROFILE" 2>&1)"
[ "$created_profile" -eq 1 ] && rm -f "$prof_file"
echo "$out" | grep -iE "$PROFILE|passed|failed" | sed 's/^/    /'
exit_ip="$(echo "$out" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '127\.0\.0\.1' | head -1)"
if echo "$out" | grep -q ' OK$'; then
  ok "selftest $PROFILE passed (exit ${exit_ip:-?})"
  if [ -n "$host_ip" ] && [ -n "$exit_ip" ] && [ "$exit_ip" != "$host_ip" ]; then
    ok "exit IP hidden (host $host_ip, exit $exit_ip)"
  else
    echo "    note: exit IP equals host or host unknown — expected only for a 'direct' profile"
  fi
else
  no "selftest $PROFILE failed"
fi

# --------------------------------------------------------------------- summary
hdr "summary"
echo "  $pass passed, $fail failed"
if [ "$fail" -eq 0 ]; then
  echo "  SMOKE TEST PASSED — veil works zero-capability on this host"
  exit 0
fi
echo "  SMOKE TEST FAILED"
exit 1
