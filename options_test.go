package oauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	oauth "github.com/Elagoht/collage-oauth"
	session "github.com/Elagoht/collage-session"
	"github.com/Elagoht/collage/pkg/collage"
	"github.com/Elagoht/collage/pkg/collagetest"
)

type stubStore struct{ rows map[string][]byte }

func (s *stubStore) Load(_ context.Context, u, p string) ([]byte, error) {
	return s.rows[u+"\x00"+p], nil
}
func (s *stubStore) Save(_ context.Context, u, p string, b []byte) error {
	if s.rows == nil {
		s.rows = map[string][]byte{}
	}
	s.rows[u+"\x00"+p] = b
	return nil
}
func (s *stubStore) Delete(_ context.Context, u, p string) error {
	delete(s.rows, u+"\x00"+p)
	return nil
}

func onLogin(context.Context, oauth.Identity) (string, error) { return "u1", nil }

func google(name string) oauth.Provider {
	return oauth.Provider{Name: name, Preset: "google", ClientID: "id", ClientSecret: "secret"}
}

// sessionPlugin is elagoht/session with a fixed key, which oauth needs before it.
func sessionPlugin() collage.Plugin {
	return session.New(session.Options{Key: bytes.Repeat([]byte{0xab}, 32)})
}

// start builds and starts an app with session and the plugin; the error is
// whichever of Configure or Init came first. config, when given, is the
// plugin's section of plugins-config.json.
func start(t *testing.T, opts oauth.Options, config ...string) error {
	t.Helper()
	options := []collagetest.SiteOption{collagetest.WithPlugins(sessionPlugin(), oauth.New(opts))}
	if len(config) > 0 {
		options = append(options, collagetest.WithPluginConfig(oauth.Name, config[0]))
	}
	_, err := collagetest.TrySite(t, options...)
	return err
}

func TestOptions_Invalid(t *testing.T) {
	t.Setenv(oauth.DefaultKeyEnv, "")
	t.Setenv("OAUTH_TEST_UNSET", "")
	t.Setenv("OAUTH_TEST_SHORT_KEY", strings.Repeat("ab", 31))
	t.Setenv("OAUTH_TEST_BAD_KEY", "zz"+strings.Repeat("ab", 31))
	t.Setenv("OAUTH_TEST_GOOD_KEY", strings.Repeat("ab", 32))
	t.Setenv("OAUTH_TEST_BLANK_KEY", "  ")
	t.Setenv("OAUTH_TEST_BAD_PREVIOUS", strings.Repeat("ef", 32)+",zz")
	t.Setenv("OAUTH_TEST_SHORT_PREVIOUS", strings.Repeat("ef", 31))
	good := func() oauth.Options {
		return oauth.Options{Providers: []oauth.Provider{google("google")}, OnLogin: onLogin}
	}
	tests := map[string]func(o *oauth.Options){
		"no providers":      func(o *oauth.Options) { o.Providers = nil },
		"empty name":        func(o *oauth.Options) { o.Providers[0].Name = "" },
		"duplicate name":    func(o *oauth.Options) { o.Providers = append(o.Providers, google("google")) },
		"unknown preset":    func(o *oauth.Options) { o.Providers[0].Preset = "nope" },
		"no preset, issuer": func(o *oauth.Options) { o.Providers[0].Preset = "" },
		"no client id":      func(o *oauth.Options) { o.Providers[0].ClientID = "" },
		"unset secret env": func(o *oauth.Options) {
			o.Providers[0].ClientSecret = ""
			o.Providers[0].ClientSecretEnv = "OAUTH_TEST_UNSET"
		},
		"no secret at all": func(o *oauth.Options) { o.Providers[0].ClientSecret = "" },
		"store, no key":    func(o *oauth.Options) { o.Store = &stubStore{} },
		"short key":        func(o *oauth.Options) { o.Key = bytes.Repeat([]byte{1}, 31) },
		"short key env":    func(o *oauth.Options) { o.KeyEnv = "OAUTH_TEST_SHORT_KEY" },
		"bad key env":      func(o *oauth.Options) { o.KeyEnv = "OAUTH_TEST_BAD_KEY" },
		"unset key env":    func(o *oauth.Options) { o.KeyEnv = "OAUTH_TEST_NEVER_SET" },
		"empty key env":    func(o *oauth.Options) { o.KeyEnv = "OAUTH_TEST_UNSET" },
		"blank key env":    func(o *oauth.Options) { o.KeyEnv = "OAUTH_TEST_BLANK_KEY" },
		"bad previous env": func(o *oauth.Options) {
			o.KeyEnv = "OAUTH_TEST_GOOD_KEY"
			o.PreviousKeysEnv = "OAUTH_TEST_BAD_PREVIOUS"
		},
		"unset previous env": func(o *oauth.Options) { o.KeyEnv = "OAUTH_TEST_GOOD_KEY"; o.PreviousKeysEnv = "OAUTH_TEST_NEVER_SET" },
		"short previous env": func(o *oauth.Options) {
			o.KeyEnv = "OAUTH_TEST_GOOD_KEY"
			o.PreviousKeysEnv = "OAUTH_TEST_SHORT_PREVIOUS"
		},
		"short previous from Go":      func(o *oauth.Options) { o.Key = testKey(); o.PreviousKeys = [][]byte{{1, 2}} },
		"provider name with NUL":      func(o *oauth.Options) { o.Providers[0].Name = "a\x00b" },
		"provider name with newline":  func(o *oauth.Options) { o.Providers[0].Name = "a\nb" },
		"provider name with DEL":      func(o *oauth.Options) { o.Providers[0].Name = "a\x7fb" },
		"no OnLogin":                  func(o *oauth.Options) { o.OnLogin = nil },
		"prefix no slash":             func(o *oauth.Options) { o.Prefix = "auth" },
		"errorPath absolute":          func(o *oauth.Options) { o.ErrorPath = "https://evil.example/x" },
		"errorPath protocol-relative": func(o *oauth.Options) { o.ErrorPath = "//evil.example" },
		"http issuer": func(o *oauth.Options) {
			o.Providers[0].Preset, o.Providers[0].Issuer = "", "http://id.example.com"
		},
		"http issuer over a preset": func(o *oauth.Options) { o.Providers[0].Issuer = "http://id.example.com" },
		"http issuer named like localhost": func(o *oauth.Options) {
			o.Providers[0].Preset, o.Providers[0].Issuer = "", "http://localhost.example.com"
		},
		"issuer without a scheme": func(o *oauth.Options) { o.Providers[0].Preset, o.Providers[0].Issuer = "", "id.example.com" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			o := good()
			mutate(&o)
			err := start(t, o)
			if err == nil {
				t.Fatal("started; want an error")
			}
			if strings.Contains(err.Error(), "zz") || strings.Contains(err.Error(), "abab") || strings.Contains(err.Error(), "efef") {
				t.Errorf("error names a byte of a key: %v", err)
			}
			if strings.Contains(name, "env") && !strings.Contains(name, "short") && !strings.Contains(err.Error(), "OAUTH_TEST_") {
				t.Errorf("err = %v, want it to name the environment variable", err)
			}
		})
	}
}

func TestOptions_Valid(t *testing.T) {
	t.Setenv("OAUTH_TEST_SECRET", "s3")
	t.Setenv("OAUTH_TEST_KEY", strings.Repeat("cd", 32))
	t.Setenv("OAUTH_TEST_PREVIOUS", strings.Repeat("ef", 32)+", "+strings.Repeat("12", 32))
	t.Setenv("OAUTH_TEST_NO_PREVIOUS", "")
	for name, o := range map[string]oauth.Options{
		"preset and Go secret": {Providers: []oauth.Provider{google("google")}, OnLogin: onLogin},
		"env secret, issuer, store, previous keys": {
			Providers: []oauth.Provider{{Name: "corp", Issuer: "https://id.example.com", ClientID: "x", ClientSecretEnv: "OAUTH_TEST_SECRET"}},
			OnLogin:   onLogin, Store: &stubStore{}, KeyEnv: "OAUTH_TEST_KEY",
			PreviousKeysEnv: "OAUTH_TEST_PREVIOUS", Prefix: "/sso/",
		},
		"Go key, empty previous env": {
			Providers: []oauth.Provider{google("google")}, OnLogin: onLogin, Store: &stubStore{},
			Key: testKey(), PreviousKeys: [][]byte{testKey()}, PreviousKeysEnv: "OAUTH_TEST_NO_PREVIOUS",
		},
		"http issuer on loopback": {
			Providers: []oauth.Provider{
				{Name: "a", Issuer: "http://localhost:9000", ClientID: "x", ClientSecret: "s"},
				{Name: "b", Issuer: "http://127.0.0.1:9000", ClientID: "x", ClientSecret: "s"},
				{Name: "c", Issuer: "http://[::1]:9000", ClientID: "x", ClientSecret: "s"},
			},
			OnLogin: onLogin,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := start(t, o); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPlugin_Identity(t *testing.T) {
	p := oauth.New(oauth.Options{})
	if p.Name() != "elagoht/oauth" || p.Version() != "0.3.1" || oauth.Name != p.Name() {
		t.Errorf("Name/Version = %q/%q", p.Name(), p.Version())
	}
}

func testKey() []byte { return bytes.Repeat([]byte{7}, 32) }

// TestOptions_KeysFromConfiguration: keyEnv and previousKeysEnv are read from
// plugins-config.json; the v0.1 keys key and previousKeys, which carried the
// secrets themselves, stop the application.
func TestOptions_KeysFromConfiguration(t *testing.T) {
	t.Setenv("OAUTH_TEST_KEY", strings.Repeat("cd", 32))
	t.Setenv("OAUTH_TEST_PREVIOUS", strings.Repeat("ef", 32))
	t.Setenv("OAUTH_TEST_SECRET", "s3")
	providers := `"providers":[{"name":"google","preset":"google","clientID":"id","clientSecretEnv":"OAUTH_TEST_SECRET"}]`
	opts := oauth.Options{OnLogin: onLogin, Store: &stubStore{}}
	if err := start(t, opts, `{`+providers+`,"keyEnv":"OAUTH_TEST_KEY","previousKeysEnv":"OAUTH_TEST_PREVIOUS"}`); err != nil {
		t.Fatalf("keyEnv/previousKeysEnv: %v", err)
	}
	if err := start(t, opts, `{`+providers+`,"keyEnv":"OAUTH_TEST_UNSET_KEY"}`); err == nil || !strings.Contains(err.Error(), "OAUTH_TEST_UNSET_KEY is not set") {
		t.Errorf("unset keyEnv: err = %v", err)
	}
	for _, old := range []string{
		`"key":"` + strings.Repeat("cd", 32) + `"`,
		`"previousKeys":["` + strings.Repeat("ef", 32) + `"]`,
	} {
		err := start(t, opts, `{`+providers+`,"keyEnv":"OAUTH_TEST_KEY",`+old+`}`)
		if err == nil || !strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s: err = %v, want unknown key", old, err)
		}
	}
}

// TestManifest_RequiresSession: oauth imports collage-session and cannot sign
// anyone in without it, so collage plugin add must add it too; and New(Options{})
// cannot start (OnLogin is Go-only), so the manifest carries a setup note.
func TestManifest_RequiresSession(t *testing.T) {
	raw, err := os.ReadFile("collage.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Requires []string `json:"requires"`
		Setup    string   `json:"setup"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.Requires, session.Name) {
		t.Errorf("requires = %q, want %s", m.Requires, session.Name)
	}
	if !strings.Contains(m.Setup, "OnLogin") {
		t.Errorf("setup = %q, want it to name OnLogin", m.Setup)
	}
}
