//go:build !pro

package persona

// Free edition: the persona system is a Veil Pro feature. The real forge
// generator, the bundled persona library, and the store apply/load logic
// live in the Pro build (//go:build pro) and are not shipped in the free
// binary. These stubs declare every persona symbol the rest of the
// codebase calls; each returns zero values plus ErrProOnly (or nil) so
// the free build compiles and degrades gracefully.

// DefaultStore reports that the persona store requires Veil Pro.
func DefaultStore() (*Store, error) { return nil, ErrProOnly }

// Forge reports that persona forging requires Veil Pro (nil result).
func Forge(name string) *Persona { return nil }

// ForgeWith reports that persona forging requires Veil Pro (nil result).
func ForgeWith(name string, opts ForgeOptions) *Persona { return nil }

// ForgeWithError reports that persona forging requires Veil Pro.
func ForgeWithError(name string, opts ForgeOptions) (*Persona, error) {
	return nil, ErrProOnly
}

// Catalog returns an empty option universe in the free build.
func Catalog() ForgeCatalog { return ForgeCatalog{} }

// Validate reports that forge options can only be validated in Veil Pro.
func (o ForgeOptions) Validate() error { return ErrProOnly }

// Load reports that loading a persona requires Veil Pro.
func (s *Store) Load(name string) (*Persona, error) { return nil, ErrProOnly }

// LoadAll reports that loading personas requires Veil Pro.
func (s *Store) LoadAll() ([]*Persona, error) { return nil, ErrProOnly }

// Save reports that saving a persona requires Veil Pro.
func (s *Store) Save(p *Persona) error { return ErrProOnly }

// Delete reports that deleting a persona requires Veil Pro.
func (s *Store) Delete(name string) error { return ErrProOnly }

// ForgeAndStore reports that forging-and-storing requires Veil Pro.
func (s *Store) ForgeAndStore(name string) (*Persona, error) { return nil, ErrProOnly }
