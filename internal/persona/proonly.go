package persona

import "errors"

// ErrProOnly is returned by the free-edition stubs for Pro-only features
// (the persona forge generator, the bundled persona library, and the
// store apply/load logic).
var ErrProOnly = errors.New("persona requires Veil Pro")
