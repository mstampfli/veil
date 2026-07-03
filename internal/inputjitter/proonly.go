package inputjitter

import "errors"

// ErrProOnly is returned by the free-edition stubs for Pro-only features.
var ErrProOnly = errors.New("behavioral jitter requires Veil Pro")
