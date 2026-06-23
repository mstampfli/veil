package tor

import (
	"strings"
)

// Circuit is one parsed line of GETINFO circuit-status output:
//
//	634 BUILT $FP1~Nick1,$FP2~Nick2,$FP3~Nick3 PURPOSE=GENERAL ...
//
// Hops carries the list of fingerprints + nicknames, in order from
// guard → middle → exit.
type Circuit struct {
	ID      string
	Status  string // LAUNCHED / BUILT / EXTENDED / FAILED / CLOSED
	Hops    []CircuitHop
	Purpose string
}

// CircuitHop is one relay in a circuit.
type CircuitHop struct {
	Fingerprint string // 40-hex
	Nickname    string
}

// ParseCircuits splits a circuit-status reply into Circuits.
func ParseCircuits(reply string) []Circuit {
	var out []Circuit
	for _, line := range strings.Split(reply, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		c := Circuit{ID: fields[0], Status: fields[1]}
		// Path field (fields[2]) is comma-separated $FP~Nick.
		for _, h := range strings.Split(fields[2], ",") {
			h = strings.TrimPrefix(h, "$")
			parts := strings.SplitN(h, "~", 2)
			hop := CircuitHop{Fingerprint: parts[0]}
			if len(parts) == 2 {
				hop.Nickname = parts[1]
			}
			c.Hops = append(c.Hops, hop)
		}
		// Purpose=... in remaining fields.
		for _, f := range fields[3:] {
			if strings.HasPrefix(f, "PURPOSE=") {
				c.Purpose = strings.TrimPrefix(f, "PURPOSE=")
			}
		}
		out = append(out, c)
	}
	return out
}

// EntryExit returns the (guard, exit) hop pair for a built circuit. If
// the circuit isn't BUILT or has fewer than 2 hops, returns zero values.
func (c Circuit) EntryExit() (entry, exit CircuitHop, ok bool) {
	if c.Status != "BUILT" || len(c.Hops) < 2 {
		return
	}
	return c.Hops[0], c.Hops[len(c.Hops)-1], true
}
