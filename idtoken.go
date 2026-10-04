package oauth

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
)

// skew is how far the provider's clock may be off from ours.
const skew = 60 * time.Second

// audience is an id_token's aud: one string or an array of them.
type audience []string

// UnmarshalJSON accepts a string or an array of strings.
func (a *audience) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		*a = nil
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("oauth: aud is neither a string nor an array of strings")
	}
	*a = many
	return nil
}

func (a audience) contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

// claims are the id_token claims the plugin reads. A claim that is absent is
// its zero value, and the checks reject a zero exp, iat or sub.
type claims struct {
	Iss           string   `json:"iss"`
	Sub           string   `json:"sub"`
	Nonce         string   `json:"nonce"`
	Azp           string   `json:"azp"`
	Email         string   `json:"email"`
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	Aud           audience `json:"aud"`
	Exp           int64    `json:"exp"`
	Iat           int64    `json:"iat"`
	EmailVerified bool     `json:"email_verified"`
}

// UnmarshalJSON reads email_verified as a bool or the string "true"/"false"
// (some providers send a string), and exp and iat as integers or floats.
func (c *claims) UnmarshalJSON(b []byte) error {
	type plain claims
	aux := struct {
		*plain
		Exp           json.RawMessage `json:"exp"`
		Iat           json.RawMessage `json:"iat"`
		EmailVerified json.RawMessage `json:"email_verified"`
	}{plain: (*plain)(c)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	var err error
	if c.EmailVerified, err = flexBool(aux.EmailVerified); err != nil {
		return err
	}
	if c.Exp, err = numericDate(aux.Exp); err != nil {
		return err
	}
	if c.Iat, err = numericDate(aux.Iat); err != nil {
		return err
	}
	return nil
}

// flexBool reads a JSON bool, or the string "true" or "false". Absent is false.
func flexBool(raw json.RawMessage) (bool, error) {
	switch string(bytes.TrimSpace(raw)) {
	case "", "null", "false", `"false"`:
		return false, nil
	case "true", `"true"`:
		return true, nil
	}
	return false, errors.New("oauth: email_verified is not a boolean")
}

// numericDate reads a JWT NumericDate, whole seconds kept. Absent is 0.
func numericDate(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil || math.IsNaN(f) || f < 0 || f > math.MaxInt32*1000 {
		return 0, errors.New("oauth: a date claim is not a number")
	}
	return int64(f), nil
}

// parseIDToken decodes the claims of an id_token. It does not check its
// signature: the token came straight from the token endpoint over TLS, which
// OpenID Connect Core 3.1.3.7 lets a client trust in place of the signature.
func parseIDToken(token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, errors.New("oauth: id_token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return claims{}, errors.New("oauth: id_token payload is not base64url")
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return claims{}, errors.New("oauth: id_token payload is not valid claims")
	}
	return c, nil
}

// checkClaims checks an id_token's claims against the provider, the pending
// sign-in's nonce and the time now. The error names the failed check, never a
// claim's value.
func checkClaims(c claims, pr *provider, meta *metadata, clientID, nonce string, now time.Time) error {
	switch {
	case c.Iss == "" || (c.Iss != meta.Issuer && !issuerMatches(pr, c.Iss)):
		return errors.New("oauth: id_token iss is not the provider's issuer")
	case !c.Aud.contains(clientID):
		return errors.New("oauth: id_token aud does not hold the client ID")
	case len(c.Aud) > 1 && c.Azp != clientID:
		return errors.New("oauth: id_token has several audiences and azp is not the client ID")
	case c.Azp != "" && c.Azp != clientID:
		return errors.New("oauth: id_token azp is not the client ID")
	case c.Exp == 0 || !now.Before(time.Unix(c.Exp, 0).Add(skew)):
		return errors.New("oauth: id_token has expired")
	case c.Iat == 0 || time.Unix(c.Iat, 0).After(now.Add(skew)):
		return errors.New("oauth: id_token is issued in the future")
	case nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1:
		return errors.New("oauth: id_token nonce does not match the sign-in")
	case c.Sub == "":
		return errors.New("oauth: id_token has no sub")
	}
	return nil
}
