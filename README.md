# elagoht/oauth

A collage plugin that signs a reader in with an OpenID Connect provider (Google,
Microsoft, GitLab or any other that publishes a discovery document) and, when you
ask, keeps the provider's API tokens so the application can call the provider on
the reader's behalf. The application keeps its own users: the plugin hands you who
the provider says the reader is, you answer with your user ID, and it signs the
reader in through [elagoht/session](https://github.com/Elagoht/collage-session), so
`session.RequireUser` guards work unchanged.

```sh
go get github.com/Elagoht/collage-oauth
```

```go
app, err := collage.New(&collage.Config{
	BaseURL: "https://example.com",
	Plugins: []collage.Plugin{
		session.New(session.Options{KeyHex: os.Getenv("SESSION_KEY")}),
		oauth.New(oauth.Options{
			Providers: []oauth.Provider{{
				Name:            "google",
				Preset:          "google",
				ClientID:        "1234-abcd.apps.googleusercontent.com",
				ClientSecretEnv: "GOOGLE_CLIENT_SECRET",
			}},
			OnLogin: func(ctx context.Context, id oauth.Identity) (string, error) {
				return users.FindOrCreate(ctx, id.Provider, id.Subject, id.Name)
			},
		}),
	},
})
```

```html
<a href="{{oauthLogin "google"}}">Sign in with Google</a>
```

Requires collage v0.50.0 or later and collage-session v0.2.3 or later. Register
elagoht/session too: without it the login routes answer `500` and log which
plugin is missing.

## How a sign-in goes

1. `{{oauthLogin "google"}}` links to `/auth/google/login?next=<the current page>`.
   `{{oauthLogin "google" "/after"}}` names `next` yourself.
2. The login route checks `next` with `collage.SafeRedirect`, keeps a one-use
   pending sign-in in the session, and answers `303` to the provider with a
   `state`, a `nonce` and a PKCE challenge.
3. The provider sends the reader back to `/auth/google/callback`. The plugin
   exchanges the code, checks the id_token's claims, and calls `OnLogin`.
4. The session gets a new ID, is signed in under `session.UserKey`, and the reader
   is sent to `next`.

Both routes answer `GET` only: a `HEAD` (a link preview) must not start or spend a
sign-in, so any other method is a `405`.

`next` must be a path on this site. An absolute URL, `//host`, `/\host`, a
backslash anywhere, a path that cleans into one of those (`/./\host`) and
`javascript:` all end at `afterLogin` instead, and so does a `next` longer than
1024 bytes, because the pending sign-in lives in the session cookie. A shorter
`next` that the session still cannot hold (it holds data of its own) also ends at
`afterLogin`. The final redirect is written exactly as checked, not cleaned again.

The session cookie must reach the callback, which is a navigation from the
provider's site: keep elagoht/session's `sameSite` at its default, `"lax"`.
With `"strict"` the browser leaves the cookie off and every sign-in fails with
`state`.

## Options

| Option | JSON | Default | |
| --- | --- | --- | --- |
| `Providers` | `providers` | | At least one, see below |
| `Prefix` | `prefix` | `"/auth"` | Where the routes live: `{prefix}/{name}/login` and `{prefix}/{name}/callback`. Starts with `/` |
| `AfterLogin` | `afterLogin` | `"/"` | Where a sign-in without a `next` ends |
| `ErrorPath` | `errorPath` | | A page on this site given `?error=<code>`; empty means the built-in status pages. Must be a path starting with a single `/`; `?error=` is added to its own query |
| `Key` | `key` (hex) | | Seals the tokens kept in `Store`: at least 32 bytes; required with `Store` |
| `PreviousKeys` | `previousKeys` (hex) | | Keys that still open what they sealed, so `Key` can be rotated |
| `OnLogin` | not configurable | | `func(ctx, Identity) (userID string, err error)`. Required. Go only |
| `Store` | not configurable | | Keeps the sealed tokens. Optional; see [API access](#api-access). Go only |
| `HTTPClient` | not configurable | 10s timeout | The `*http.Client` for calls to the provider. Go only |

A provider:

| Option | JSON | |
| --- | --- | --- |
| `Name` | `name` | The URL segment, one segment without control characters, unique. Required |
| `Preset` | `preset` | `"google"`, `"microsoft"` or `"gitlab"`: fills the issuer and the provider's own parameters |
| `Issuer` | `issuer` | The OpenID Connect issuer. Its `/.well-known/openid-configuration` is read. With a preset it overrides the preset's issuer (one Microsoft tenant, say). `https`, or `http` only to `localhost` or a loopback IP |
| `ClientID` | `clientID` | Required |
| `ClientSecretEnv` | `clientSecretEnv` | The name of the environment variable holding the client secret |
| `ClientSecret` | not configurable | The secret, set from Go instead |
| `Scopes` | `scopes` | Asked for besides `openid email profile` |
| `Offline` | `offline` | Ask for a refresh token |

A preset or an issuer is needed. With both, the preset gives its parameters and
the issuer replaces the preset's. A client secret that is set is needed too (an
empty environment variable is not set). The application does not start for any
of: no providers, a provider without a name or with a name used twice, an unknown
preset, neither preset nor issuer, an issuer that is not `https` (plain `http` is
allowed only to `localhost` and loopback IPs), no client ID, no client secret, a
`Store` without a `Key`, a key under 32 bytes or not valid hex (the error names no
byte of it), no `OnLogin`, a prefix that does not start with `/`, an `errorPath`
that is not a path on this site.

```json
{
  "elagoht/oauth": {
    "providers": [
      { "name": "google", "preset": "google", "clientID": "1234-abcd.apps.googleusercontent.com",
        "clientSecretEnv": "GOOGLE_CLIENT_SECRET", "offline": true }
    ],
    "afterLogin": "/account",
    "errorPath": "/sign-in-failed",
    "key": "9f2c...64 hex digits..."
  }
}
```

Keep the secret and the key out of a file under version control. `OnLogin` and
`Store` are code, so configuration alone is not enough: set them in Go on the
plugin's options.

### Presets

| Preset | Issuer | With `offline` |
| --- | --- | --- |
| `google` | `https://accounts.google.com` | `access_type=offline&prompt=consent` |
| `microsoft` | `https://login.microsoftonline.com/common/v2.0`; a tenant-specific issuer is accepted | the `offline_access` scope |
| `gitlab` | `https://gitlab.com` | nothing added: GitLab gives a refresh token with every code exchange |
| none (an `issuer`) | the configured one | the `offline_access` scope, as OpenID Connect asks |

**The `microsoft` preset alone accepts any Entra ID tenant and any personal
Microsoft account.** It uses the `common` endpoint, so every work, school and
personal account can sign in. To admit one organisation only, set `issuer` to its
tenant, `https://login.microsoftonline.com/<tenant-id>/v2.0`: with an `issuer` set,
the issuer must match it exactly. Microsoft's id_token has no `email_verified`
claim, so `EmailVerified` is always false for it; do not match accounts by its
e-mail.

Discovery is read on first use, not at start, so a site still starts when a
provider is down. It is cached for an hour; a failed read is not cached. A document
whose `issuer` is not the configured one is refused, and so is one that names an
authorization, token, userinfo or revocation endpoint that is not `https` (or
`http` to loopback); the sign-in then ends with `unavailable`. Calls to the token
and revocation endpoints never follow a redirect, so a `307` cannot send the client
secret to another host.

## OnLogin

```go
func(ctx context.Context, id oauth.Identity) (userID string, err error)
```

`Identity` has `Provider`, `Subject`, `Email`, `EmailVerified`, `Name` and
`Picture`. The id_token's claims have been checked by then. Return your user's ID,
creating the user if this is the first time; an error or an empty ID ends the
sign-in with `rejected`.

- **Key accounts on `Provider` + `Subject`.** `Subject` is the provider's stable ID
  for the reader. An e-mail address can change hands, and two providers may name
  the same address.
- **Trust the e-mail only when `EmailVerified` is true.** Never match an existing
  account by an unverified address: that is how one reader takes over another's
  account.

When the id_token carries no e-mail and the provider has a userinfo endpoint, the
plugin asks it, and its `sub` must equal the id_token's. A userinfo answer that is
a signed JWT (`application/jwt`) is not supported.

A reader who signs in while the session already belongs to a different user has that
session cleared first, so nothing of the other user carries over. The same user
signing in again keeps the session's data under a new ID.

## API access

Give the plugin a `Store` and a `Key`, and the provider's tokens are kept for each
user, so the application can call the provider's API later (ask for the scopes you
need in `scopes`, and set `offline` to get a refresh token):

```go
type TokenStore interface {
	Load(ctx context.Context, userID, provider string) ([]byte, error) // (nil, nil) when none
	Save(ctx context.Context, userID, provider string, sealed []byte) error
	Delete(ctx context.Context, userID, provider string) error
}
```

The `Store` sees opaque bytes. Tokens are sealed with AES-256-GCM under a key
derived from `Key`, and the blob is bound to the user and provider it was saved
for, so a blob copied to another row does not open. The `Key` is at least 32 bytes:
`openssl rand -hex 32` makes one. To rotate it, set the new one as `Key` and move
the old one to `PreviousKeys`; a token opened with a previous key is sealed again
with `Key` the next time it is saved.

```go
plug := oauth.New(opts)

client, err := plug.Client(ctx, userID, "google")
if errors.Is(err, oauth.ErrNotLinked) {
	// no usable token: send the reader through sign-in again
}
resp, err := client.Get("https://www.googleapis.com/drive/v3/files")
```

- **`Client`** returns an `*http.Client` that sends the user's access token as a
  bearer token. It asks for a valid token on every request and refreshes it when
  less than 60 seconds are left, so a client kept for a long time keeps working.
  A refresh token the provider rotates replaces the old one. A call that answers
  `401` is not retried.
- **`ErrNotLinked`** means there is nothing usable: no `Store`, no row, an expired
  token with no refresh token, or a refresh the provider refused with
  `invalid_grant` (the row is deleted). Other errors, such as a store failure, come
  back as they are.
- **`Revoke(ctx, userID, provider)`** asks the provider's revocation endpoint, when
  it has one, to revoke the token, then deletes the row. The row is deleted even
  when the provider's call fails, and that error is returned afterwards.
- A sign-in that returns no refresh token (providers often send one only the first
  time) keeps the one already stored. A token whose lifetime the provider did not
  state (`expires_in` missing) is treated as valid and never refreshed.
- A failure to save the tokens is logged, without the token, and the sign-in still
  completes; `Client` answers `ErrNotLinked` until the next sign-in.

The token is sent only where the first request went: to its host or its
subdomains, also when the client follows a redirect, and never on a redirect from
`https` to `http`. Over plain `http` it goes only to `localhost` and loopback IP
addresses; any other plain-`http` request fails. A redirect to another host is
still followed, without the token.

## Redirect URIs

Register `{origin}{prefix}/{name}/callback` with the provider, for example
`https://example.com/auth/google/callback`. The origin is `Config.BaseURL`, or
what an origin resolver such as elagoht/tenant says for the request's host, so on a
multi-tenant site **each host's callback must be registered**, one per tenant. A
development server with no `BaseURL` uses `http://<the request's host>`; a
production one without an origin answers `500` and logs that `BaseURL` is needed.

## Errors

A failed sign-in leaves no one signed in, and the pending sign-in is spent. With
`errorPath` set, the reader is sent there (`303`) with `?error=<code>`; otherwise
the site's own status page is shown.

| Code | Status | When |
| --- | --- | --- |
| `unavailable` | 503 | Discovery or the provider could not be reached |
| `state` | 400 | No pending sign-in (cookies blocked, a direct visit, a second tab replaced it, a replay), or `state` does not match |
| `expired` | 400 | More than 10 minutes since login |
| `denied` | 400 | The provider answered with an `error` (the reader said no) |
| `rejected` | 400 | `OnLogin` returned an error or an empty user ID |
| `exchange` | 502 | The code exchange (or the userinfo call) failed |
| `token` | 502 | The id_token failed a check: issuer, audience, authorized party, expiry, issued-at, nonce, subject, or the userinfo `sub` |

An unknown provider name in the URL is a `404`. Nothing about a token, a code, a
secret or a key is ever logged.

## Logout

The plugin has no logout route. Clear the session in your own action; call
`Revoke` too if the reader should also be unlinked from the provider:

```go
collage.NewAction("logout").WithPath("en", "/logout").WithMethods(http.MethodPost).
	WithHandler(func(ctx context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
		s := session.Get(rc)
		if userID := s.Get(session.UserKey); userID != "" {
			_ = plug.Revoke(ctx, userID, "google") // optional
		}
		s.Clear()
		return &collage.ActionResult{Location: "/"}, nil
	}).Build()
```

## Limits

- **No GitHub.** It is not an OpenID Connect provider. A later preset may read its
  `/user`.
- **No account linking.** Adding a provider to an account that is already signed in
  is not supported; a sign-in with another provider asks `OnLogin` like any other.
- **No signature check on the id_token.** It comes straight from the token endpoint
  over TLS, which OpenID Connect Core 3.1.3.7 allows in place of the check, so its
  claims are checked and its signature is not.
- **Refresh coalescing is per process.** Concurrent refreshes for one user and
  provider make one call within a process; several instances may each refresh, and
  a provider that rotates refresh tokens strictly can then refuse one of them.
- **Guard and action redirects stay unchecked.** Only `next` is validated, by
  `collage.SafeRedirect`.
