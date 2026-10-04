package oauth_test

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	oauth "github.com/Elagoht/collage-oauth"
	session "github.com/Elagoht/collage-session"
	"github.com/Elagoht/collage/pkg/collage"
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

// start builds an app with the plugin and starts it; the error is whichever
// of collage.New (Configure) or Start (Init) came first.
func start(t *testing.T, opts oauth.Options) error {
	t.Helper()
	app, err := collage.New(&collage.Config{
		Server:   collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{"t/p.html": {Data: []byte(`<p>hi</p>`)}}, Root: "t"},
		Plugins:  []collage.Plugin{session.New(session.Options{KeyHex: strings.Repeat("ab", 32)}), oauth.New(opts)},
	})
	if err != nil {
		return err
	}
	return app.Start()
}

func TestOptions_Invalid(t *testing.T) {
	t.Setenv("OAUTH_TEST_UNSET", "")
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
		"short key hex": func(o *oauth.Options) {
			o.KeyHex = strings.Repeat("ab", 31)
		},
		"bad key hex":                 func(o *oauth.Options) { o.KeyHex = "zz" + strings.Repeat("ab", 31) },
		"bad previous hex":            func(o *oauth.Options) { o.KeyHex = strings.Repeat("ab", 32); o.PreviousKeysHex = []string{"zz"} },
		"provider name with NUL":      func(o *oauth.Options) { o.Providers[0].Name = "a\x00b" },
		"provider name with newline":  func(o *oauth.Options) { o.Providers[0].Name = "a\nb" },
		"provider name with DEL":      func(o *oauth.Options) { o.Providers[0].Name = "a\x7fb" },
		"no OnLogin":                  func(o *oauth.Options) { o.OnLogin = nil },
		"prefix no slash":             func(o *oauth.Options) { o.Prefix = "auth" },
		"errorPath absolute":          func(o *oauth.Options) { o.ErrorPath = "https://evil.example/x" },
		"errorPath protocol-relative": func(o *oauth.Options) { o.ErrorPath = "//evil.example" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			o := good()
			mutate(&o)
			err := start(t, o)
			if err == nil {
				t.Fatal("started; want an error")
			}
			if strings.Contains(name, "bad") && strings.Contains(err.Error(), "zz") {
				t.Errorf("error names a byte of the key: %v", err)
			}
			if strings.Contains(name, "bad") && !strings.Contains(err.Error(), "oauth: key is not valid hex") {
				t.Errorf("err = %v, want the fixed hex message", err)
			}
		})
	}
}

func TestOptions_Valid(t *testing.T) {
	t.Setenv("OAUTH_TEST_SECRET", "s3")
	for name, o := range map[string]oauth.Options{
		"preset and Go secret": {Providers: []oauth.Provider{google("google")}, OnLogin: onLogin},
		"env secret, issuer, store, previous keys": {
			Providers: []oauth.Provider{{Name: "corp", Issuer: "https://id.example.com", ClientID: "x", ClientSecretEnv: "OAUTH_TEST_SECRET"}},
			OnLogin:   onLogin, Store: &stubStore{}, KeyHex: strings.Repeat("cd", 32),
			PreviousKeysHex: []string{strings.Repeat("ef", 32)}, Prefix: "/sso/",
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
	if p.Name() != "elagoht/oauth" || p.Version() != "0.1.0" || oauth.Name != p.Name() {
		t.Errorf("Name/Version = %q/%q", p.Name(), p.Version())
	}
}
