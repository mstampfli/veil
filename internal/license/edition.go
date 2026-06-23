package license

// ActiveCaps returns the capability set for the running binary. Pro features
// require BOTH the Pro edition (built with -tags pro) AND a valid, unexpired,
// unrevoked signed license. A Pro build with no valid license degrades to the
// free capability set (it does not crash); the free edition is always free.
func ActiveCaps() Capabilities {
	if proEdition && LoadFromDefault().IsPro() {
		return CapsFor(Pro)
	}
	return CapsFor(Free)
}

// ProEdition reports whether this binary was built as the Pro edition.
func ProEdition() bool { return proEdition }
