//go:build !pro

package license

// proEdition is false in the free edition: Pro features are gated off and no
// Pro code is compiled into this binary.
const proEdition = false
