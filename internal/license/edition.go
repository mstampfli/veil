package license

// proActive is the single gate for every Pro entry point. Pro features require
// BOTH the Pro edition (built with -tags pro) AND a valid, unexpired, unrevoked
// signed license. Activation is purely a logging ping (the seller's visibility
// into how widely a license is used); it never gates Pro, so honest offline and
// airgapped machines always keep working.
func proActive() bool {
	return proEdition && LoadFromDefault().IsPro()
}

// ActiveCaps returns the capability set for the running binary. A Pro build with
// no valid license degrades to the free capability set (it does not crash); the
// free edition is always free.
func ActiveCaps() Capabilities {
	if proActive() {
		return CapsFor(Pro)
	}
	return CapsFor(Free)
}

// ProEdition reports whether this binary was built as the Pro edition.
func ProEdition() bool { return proEdition }
