package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// sealVersion is the first byte of every sealed blob.
const sealVersion = 1

// stored is what the plugin keeps sealed for one user and provider.
type stored struct {
	AccessToken  string   `json:"a"`
	RefreshToken string   `json:"r"`
	Expiry       int64    `json:"e"` // Unix seconds; 0 = the provider gave no lifetime, treated as valid
	Scopes       []string `json:"s"`
}

var (
	errNoKey     = errors.New("oauth: no key to seal with")
	errBadSealed = errors.New("oauth: sealed token does not open")
)

// aead derives the AES-256-GCM cipher for key: HMAC-SHA256(key, "oauth-tokens").
func aead(key []byte) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("oauth-tokens"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealAAD binds a blob to its row; the separator keeps the pair unambiguous.
func sealAAD(userID, provider string) []byte {
	return []byte(userID + "\x00" + provider)
}

// seal encrypts t under Key as [version][nonce][ciphertext].
func (p *Plugin) seal(userID, provider string, t stored) ([]byte, error) {
	if len(p.keys) == 0 {
		return nil, errNoKey
	}
	g, err := aead(p.keys[0])
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1, 1+g.NonceSize()+len(plain)+g.Overhead())
	out[0] = sealVersion
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out = append(out, nonce...)
	return g.Seal(out, nonce, plain, sealAAD(userID, provider)), nil
}

// open decrypts blob with Key, then each previous key. withCurrent reports
// whether Key opened it, so the caller can seal it again under Key.
func (p *Plugin) open(userID, provider string, blob []byte) (t stored, withCurrent bool, err error) {
	if len(blob) == 0 || blob[0] != sealVersion {
		return stored{}, false, errBadSealed
	}
	for i, key := range p.keys {
		g, err := aead(key)
		if err != nil {
			continue
		}
		n := g.NonceSize()
		if len(blob) < 1+n+g.Overhead() {
			return stored{}, false, errBadSealed
		}
		plain, err := g.Open(nil, blob[1:1+n], blob[1+n:], sealAAD(userID, provider))
		if err != nil {
			continue
		}
		if err := json.Unmarshal(plain, &t); err != nil {
			return stored{}, false, errBadSealed
		}
		return t, i == 0, nil
	}
	return stored{}, false, errBadSealed
}
