//go:build !linux

package main

// veil-bridge runs only on Linux in practice — the cmd is unusable
// elsewhere — but the package needs to compile under cross-builds
// from CI that target non-Linux for the rest of the tree. The stub
// no-ops the cap dance.
func raiseAmbientCapNetAdmin() error { return nil }
