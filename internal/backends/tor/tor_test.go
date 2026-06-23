package tor

import "testing"

// TestPickDistinctPorts proves the draw never returns a duplicate (the
// bug this guards: two Tor listeners on the same port -> bind failure ->
// launch fails) and stays in the ephemeral range. Many iterations make a
// regression of the distinctness guarantee statistically certain to trip.
func TestPickDistinctPorts(t *testing.T) {
	for iter := 0; iter < 2000; iter++ {
		ports, err := pickDistinctPorts(4)
		if err != nil {
			t.Fatalf("iter %d: %v", iter, err)
		}
		if len(ports) != 4 {
			t.Fatalf("iter %d: got %d ports, want 4", iter, len(ports))
		}
		seen := map[int]bool{}
		for _, p := range ports {
			if p < 49152 || p > 65535 {
				t.Fatalf("iter %d: port %d out of ephemeral range", iter, p)
			}
			if seen[p] {
				t.Fatalf("iter %d: duplicate port %d in %v", iter, p, ports)
			}
			seen[p] = true
		}
	}
}
