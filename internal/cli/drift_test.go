package cli

import (
	"bytes"
	"strings"
	"testing"
	"text/tabwriter"
)

// TestDriftRowFormatter verifies the row helper formats correctly for
// each match category (ok / DRIFT / no-claim).
func TestDriftRowFormatter(t *testing.T) {
	cases := []struct {
		label, want, got string
		expectMatch      string
	}{
		{"country", "DE", "DE", "ok"},
		{"country", "DE", "US", "DRIFT"},
		{"city", "", "Berlin", "(no claim)"},
		{"asn", "", "", "(no claim)"},
		{"ip", "1.2.3.4", "1.2.3.4", "ok"},
		{"ip", "1.2.3.4", "5.6.7.8", "DRIFT"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
		row(tw, c.label, c.want, c.got)
		tw.Flush()
		out := buf.String()
		if !strings.Contains(out, c.expectMatch) {
			t.Errorf("row(%s, %q, %q): expected match %q in %q",
				c.label, c.want, c.got, c.expectMatch, out)
		}
		if !strings.Contains(out, c.label) {
			t.Errorf("row(%s, ...): label not in output %q", c.label, out)
		}
	}
}

// TestDriftRowDashForEmpty verifies that empty want/got render as "—".
func TestDriftRowDashForEmpty(t *testing.T) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	row(tw, "city", "", "")
	tw.Flush()
	out := buf.String()
	if !strings.Contains(out, "—") {
		t.Errorf("expected em-dash for empty fields, got %q", out)
	}
}

// TestDriftRowCaseInsensitive verifies that case differences in want/got
// don't trigger false drift.
func TestDriftRowCaseInsensitive(t *testing.T) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	row(tw, "country", "de", "DE")
	tw.Flush()
	out := buf.String()
	if !strings.Contains(out, "ok") {
		t.Errorf("case difference should still match: got %q", out)
	}
	if strings.Contains(out, "DRIFT") {
		t.Errorf("case difference falsely flagged drift: %q", out)
	}
}
