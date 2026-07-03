//go:build !linux

package engine

// User-ns child path is Linux-only — Windows and Darwin engines have
// their own privilege models. The setupNetnsDir stub on those
// platforms keeps the package compiling without bringing in the
// Linux-specific syscalls.
func setupNetnsDir() error { return nil }
