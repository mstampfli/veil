// Package personaextension bundles the Veil persona WebExtension and
// exposes a function to install it into a browser's data_dir at
// launch time.
//
// On Chromium-family browsers the extension loads via the
// --load-extension command-line flag (Veil appends it after writing
// the dir). On Firefox, signed XPI install is required for stable
// Firefox; auto-install is left as future work — the extension dir
// can still be loaded manually via about:debugging if the user wants.
package personaextension

import (
	"embed"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed _embed/*
var bundle embed.FS

// WriteAndPersona writes the bundled WebExtension files into
// <dataDir>/veil-persona-extension/ along with a persona.json that
// the extension's content script reads at document_start. Returns
// the absolute path to the extension dir for use with
// --load-extension on Chromium-family browsers.
//
// pers is encoded as the persona JSON the content script consumes.
// Pass nil to write the bundle without a persona (extension becomes
// a no-op until persona.json is added).
func WriteAndPersona(dataDir string, pers any) (string, error) {
	return WriteAndPersonaWithFlags(dataDir, pers, nil)
}

// WriteAndPersonaWithFlags is WriteAndPersona plus arbitrary top-level
// fields merged into persona.json. Used to thread engine-side state
// (e.g. _veil_brave_shields_active) into the extension at document_start
// so the content script can avoid stacking farbling on top of Brave
// Shields' C++ farbling.
//
// browserFamily ("chromium" / "firefox" / "") controls which background
// stanza the manifest gets:
//   - chromium: { "service_worker": "background.js" }   (MV3 standard)
//   - firefox:  { "scripts": ["background.js"] }        (Firefox MV3)
//   - "":       service_worker (default)
//
// Mixing the two breaks Chrome (pre-121 MV3 rejects the manifest if
// background.scripts is present); Firefox stable doesn't honor
// background.service_worker. Caller passes the preset's family.
func WriteAndPersonaWithFlagsForBrowser(dataDir, browserFamily string, pers any, flags map[string]any) (string, error) {
	dest, err := WriteAndPersonaWithFlags(dataDir, pers, flags)
	if err != nil {
		return dest, err
	}
	if err := patchManifestForBrowser(dest, browserFamily); err != nil {
		return dest, err
	}
	return dest, nil
}

// patchManifestForBrowser rewrites manifest.json's background stanza
// so each browser sees only the field it understands.
func patchManifestForBrowser(extDir, family string) error {
	manifestPath := filepath.Join(extDir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	bg, _ := m["background"].(map[string]any)
	if bg == nil {
		bg = map[string]any{}
	}
	switch family {
	case "firefox":
		// Firefox MV3 stable: scripts array; remove service_worker
		// (it's behind a flag and we don't want to depend on it).
		bg = map[string]any{"scripts": []any{"background.js"}}
	default:
		// Chromium-family: service_worker only. background.scripts
		// in MV3 is rejected by Chrome <121 and ignored after.
		bg = map[string]any{"service_worker": "background.js"}
	}
	m["background"] = bg
	patched, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath, patched, 0o644)
}

// WriteAndPersonaWithFlags is the legacy entry that defaults to the
// Chromium manifest. Existing callers that want browser-specific
// manifests should use WriteAndPersonaWithFlagsForBrowser.
func WriteAndPersonaWithFlags(dataDir string, pers any, flags map[string]any) (string, error) {
	if dataDir == "" {
		return "", os.ErrInvalid
	}
	dest := filepath.Join(dataDir, "veil-persona-extension")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}

	// Walk the embedded _embed/ tree and copy every file out.
	if err := fs.WalkDir(bundle, "_embed", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := bundle.ReadFile(path)
		if err != nil {
			return err
		}
		// Strip the "_embed/" prefix.
		rel := path
		if len(rel) > len("_embed/") && rel[:len("_embed/")] == "_embed/" {
			rel = rel[len("_embed/"):]
		}
		out := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		return os.WriteFile(out, data, 0o644)
	}); err != nil {
		return "", err
	}

	// Write persona.json — the file the content script reads
	// synchronously at document_start to learn what to override.
	personaPath := filepath.Join(dest, "persona.json")
	merged := map[string]any{}
	if pers != nil {
		// Re-encode pers via JSON so a struct with json: tags collapses
		// into a flat map we can extend.
		raw, err := json.Marshal(pers)
		if err != nil {
			return "", err
		}
		if len(raw) > 0 && raw[0] == '{' {
			if err := json.Unmarshal(raw, &merged); err != nil {
				return "", err
			}
		}
	}
	for k, v := range flags {
		merged[k] = v
	}
	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(personaPath, data, 0o644); err != nil {
		return "", err
	}
	// Also emit persona-data.js — persona.json content inlined into a
	// JS file. Content scripts running in MAIN world have NO access to
	// chrome.runtime / browser.runtime (those are isolated-world APIs).
	// Without this file the content script's chrome.runtime.getURL
	// throws, persona stays null, and EVERY override silently no-ops
	// while the real device leaks through. Persona-data.js is listed
	// FIRST in manifest content_scripts.js so it runs before
	// persona-overrides.js and parks the persona on a window-global
	// the overrides script reads.
	dataJS := []byte("// Auto-generated by Veil — do not edit by hand.\n" +
		"window.__veil_persona_data = " + string(data) + ";\n")
	if err := os.WriteFile(filepath.Join(dest, "persona-data.js"), dataJS, 0o644); err != nil {
		return "", err
	}

	return dest, nil
}

// ChownTo recursively sets uid/gid on the extension dir. Used after
// install when veil-gui runs as root via pkexec but the launched
// browser runs as a target user — the extension files must be
// readable by the browser's uid.
func ChownTo(extDir string, uid, gid int) error {
	if uid <= 0 {
		return nil
	}
	return filepath.Walk(extDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}
