package profile

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"
)

// Export serializes a profile and encrypts it with a passphrase using age.
// Output is ASCII-armored age ciphertext.
func Export(p *Profile, passphrase string, w io.Writer) error {
	if passphrase == "" {
		return fmt.Errorf("passphrase required")
	}
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	armored := armor.NewWriter(w)
	enc, err := age.Encrypt(armored, r)
	if err != nil {
		armored.Close()
		return err
	}
	if err := yaml.NewEncoder(enc).Encode(p); err != nil {
		enc.Close()
		armored.Close()
		return err
	}
	if err := enc.Close(); err != nil {
		armored.Close()
		return err
	}
	return armored.Close()
}

// Import reads an age-encrypted profile bundle.
func Import(passphrase string, r io.Reader) (*Profile, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase required")
	}
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	armored := armor.NewReader(r)
	dec, err := age.Decrypt(armored, id)
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, dec); err != nil {
		return nil, err
	}
	var p Profile
	if err := yaml.Unmarshal(buf.Bytes(), &p); err != nil {
		return nil, err
	}
	return &p, nil
}
