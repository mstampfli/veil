package chain

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/mstampfli/veil/internal/profile"
)

// Randomize takes a chain of candidate hops and produces a runtime chain
// according to the rules:
//
//   - Mandatory hops are always included.
//   - Optional hops are independently included with 50% probability.
//   - Hops with neither flag (the default) are always included.
//   - Result order matches the candidate order (we don't reorder; that
//     would risk producing chains chain.Validate rejects).
//
// If the result is empty (e.g. all hops marked optional and all dropped)
// or fails Validate, Randomize falls back to the original chain.
func Randomize(c []profile.Backend) []profile.Backend {
	if len(c) == 0 {
		return c
	}
	out := make([]profile.Backend, 0, len(c))
	for _, b := range c {
		if b.Mandatory {
			out = append(out, b)
			continue
		}
		if b.Optional {
			if coinflip() {
				out = append(out, b)
			}
			continue
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return c
	}
	if err := Validate(out); err != nil {
		return c
	}
	return out
}

// coinflip returns true ~50% of the time using crypto/rand so the result
// is unpredictable and not influenced by Go's math/rand seed.
func coinflip() bool {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]&1 == 1
}

// PickIndex returns a uniform random integer in [0, n). Used by the engine
// to pick a random hop pool entry. Returns -1 if n <= 0.
func PickIndex(n int) int {
	if n <= 0 {
		return -1
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint64(b[:]) % uint64(n))
}

// SummaryWith renders a chain with annotations like "(mandatory)" /
// "(optional)" so the GUI can show what's in the candidate pool.
func SummaryWith(c []profile.Backend) string {
	parts := make([]string, len(c))
	for i, b := range c {
		s := string(b.Kind)
		if b.Mandatory {
			s += "*"
		} else if b.Optional {
			s += "?"
		}
		parts[i] = s
	}
	return fmt.Sprint(parts)
}
