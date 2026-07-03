package engine

import "errors"

// errProOnly is returned by the FREE-build stubs for engine features
// that ship only in Veil Pro. The real implementations live in files
// tagged `//go:build pro`; the matching `!pro` stubs return this so a
// free binary fails closed instead of silently skipping the feature.
var errProOnly = errors.New("this is a Veil Pro feature")
