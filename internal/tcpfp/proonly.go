package tcpfp

import "errors"

// ErrProOnly is returned by the free-edition stubs for Pro-only features.
var ErrProOnly = errors.New("TCP fingerprinting requires Veil Pro")
