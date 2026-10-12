package oauth

import (
	"context"
	"errors"
	"net/http"
)

// Options configures the plugin. In configuration the keys are the json names.
type Options struct {
	// Providers are the identity providers a reader may sign in with. At least one.
	Providers []Provider `json:"providers"`
	// Prefix is where the login routes live: {prefix}/{provider}/login and
	// {prefix}/{provider}/callback. It starts with "/". Default "/auth".
	Prefix string `json:"prefix"`
	// AfterLogin is where a sign-in without a next ends. Default "/".
	AfterLogin string `json:"afterLogin"`
	// ErrorPath is a page given ?error=<code> when a sign-in fails. Empty means
	// the built-in status pages.
	ErrorPath string `json:"errorPath"`
	// KeyEnv names the environment variable holding Key, hex-encoded. When set,
	// it wins over Key, and an unset, empty or non-hex variable is an error.
	KeyEnv string `json:"keyEnv"`
	// Key seals the tokens kept in Store, so it is required with Store. At least
	// 32 bytes. Set from Go; configuration names it with KeyEnv.
	Key []byte `json:"-"`
	// PreviousKeysEnv names the environment variable holding PreviousKeys,
	// hex-encoded and comma-separated. When set, it wins over PreviousKeys; a
	// variable that is not set, or a key in it that is not hex, is an error, and
	// one set but empty is no previous keys.
	PreviousKeysEnv string `json:"previousKeysEnv"`
	// PreviousKeys still open what they sealed, so Key can be rotated. A token
	// opened with one is sealed again with Key the next time it is saved. Set
	// from Go; configuration names them with PreviousKeysEnv.
	PreviousKeys [][]byte `json:"-"`

	// OnLogin turns a verified identity into the application's user ID, creating
	// the user when it must. Required. An error ends the sign-in.
	OnLogin LoginFunc `json:"-"`
	// Store keeps the sealed tokens. Optional: without it no token is kept, and
	// Client always answers ErrNotLinked.
	Store TokenStore `json:"-"`
	// HTTPClient makes the calls to the provider. Default: a 10 second timeout.
	HTTPClient *http.Client `json:"-"`
}

// Provider is one identity provider.
type Provider struct {
	// Name is the URL segment: {prefix}/{name}/login. Unique.
	Name string `json:"name"`
	// Preset fills the issuer and the provider's own parameters: "google",
	// "microsoft" or "gitlab".
	Preset string `json:"preset"`
	// Issuer is the OpenID Connect issuer. With a Preset it replaces the preset's
	// issuer (one Microsoft tenant) and must then be matched exactly. https, or
	// http only to localhost or a loopback IP.
	Issuer string `json:"issuer"`
	// ClientID is the application's ID at the provider. Required.
	ClientID string `json:"clientID"`
	// ClientSecretEnv names the environment variable that holds the client secret.
	ClientSecretEnv string `json:"clientSecretEnv"`
	// ClientSecret is the client secret, when it is set from Go.
	ClientSecret string `json:"-"`
	// Scopes are asked for besides "openid email profile".
	Scopes []string `json:"scopes"`
	// Offline asks the provider for a refresh token: the preset's way, or the
	// offline_access scope when there is no preset.
	Offline bool `json:"offline"`
}

// Identity is who the provider says the reader is, once its id_token is verified.
type Identity struct {
	Provider      string // the Provider's Name
	Subject       string // the provider's stable ID for the reader ("sub")
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

// LoginFunc turns an Identity into the application's user ID.
type LoginFunc func(ctx context.Context, id Identity) (userID string, err error)

// TokenStore keeps sealed tokens, one row per user and provider. The plugin
// seals them before Save and opens them after Load; the store sees only bytes.
type TokenStore interface {
	// Load returns the sealed token, or (nil, nil) when there is none.
	Load(ctx context.Context, userID, provider string) ([]byte, error)
	Save(ctx context.Context, userID, provider string, sealed []byte) error
	Delete(ctx context.Context, userID, provider string) error
}

// ErrNotLinked is returned when there is no usable token for the user and provider.
var ErrNotLinked = errors.New("oauth: no usable token for this user and provider")
