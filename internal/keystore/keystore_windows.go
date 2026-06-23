//go:build windows

package keystore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows backend: DPAPI (Data Protection API). CryptProtectData
// encrypts a blob with a key derived from the current Windows user's
// login credentials; only the same user account on the same machine
// can decrypt. The encrypted blob is then stored on disk under
// %LOCALAPPDATA%\Veil\keystore\<name-hash>.dpapi — ciphertext at rest,
// no plaintext key on disk even if Veil is uninstalled or the dir
// is exfiltrated.
//
// DPAPI does NOT need any always-on service the way libsecret does:
// it's a synchronous Win32 call backed by lsass.exe. So Available()
// is essentially "is this Windows" — true unless we're running on
// a server SKU with extreme stripping that nobody ships.

var (
	crypt32                = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(d)), pbData: &d[0]}
}

func (b *dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

const (
	cryptprotectUIForbidden = 0x1
)

func encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	in := newBlob(plaintext)
	out := &dataBlob{}
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(in)),
		0, // szDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		uintptr(cryptprotectUIForbidden),
		uintptr(unsafe.Pointer(out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return out.bytes(), nil
}

func decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}
	in := newBlob(ciphertext)
	out := &dataBlob{}
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(in)),
		0,
		0,
		0,
		0,
		uintptr(cryptprotectUIForbidden),
		uintptr(unsafe.Pointer(out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return out.bytes(), nil
}

// keystoreDir is %LOCALAPPDATA%\Veil\keystore. Per-user, never roams
// to other machines (that's intentional — a DPAPI ciphertext from
// machine A doesn't decrypt on machine B anyway).
func keystoreDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "Veil", "keystore")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// hashName turns an arbitrary key name into a fixed-width filename so
// long dataDir paths don't blow up MAX_PATH.
func hashName(name string) string {
	h := sha256.Sum256([]byte(Service + ":" + name))
	return hex.EncodeToString(h[:16])
}

func entryPath(name string) (string, error) {
	dir, err := keystoreDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, hashName(name)+".dpapi"), nil
}

// Available reports whether DPAPI encrypt+decrypt round-trips cleanly
// for this user. Catches degenerate edge cases (corrupt user profile,
// missing crypt32) without forcing every keystore call to retry.
func Available() bool {
	enc, err := encrypt([]byte("veil-keystore-probe"))
	if err != nil || len(enc) == 0 {
		return false
	}
	dec, err := decrypt(enc)
	if err != nil {
		return false
	}
	return string(dec) == "veil-keystore-probe"
}

// Get retrieves the secret stored under name, decrypting via DPAPI.
func Get(name string) ([]byte, error) {
	p, err := entryPath(name)
	if err != nil {
		return nil, err
	}
	cipher, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	plain, err := decrypt(cipher)
	if err != nil {
		return nil, err
	}
	if len(plain) == 0 {
		return nil, ErrNotFound
	}
	return plain, nil
}

// Set encrypts and stores the secret under name.
func Set(name string, secret []byte) error {
	p, err := entryPath(name)
	if err != nil {
		return err
	}
	cipher, err := encrypt(secret)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, cipher, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Delete removes a stored secret. Idempotent.
func Delete(name string) error {
	p, err := entryPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// silence "imported and not used" when a future refactor drops syscall.
var _ = syscall.Handle(0)
