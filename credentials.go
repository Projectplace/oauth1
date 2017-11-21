package oauth1

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
)

// ClientCredentials holds the identifier and shared secret used to
// authenticate a particular client.
type ClientCredentials struct {
	ID     string
	Secret string

	// Callback is an optional pre-configured callback URI for the client.
	// It is only used if Server.FixedCallbacks is set to true.
	Callback *url.URL

	// Custom is an extension slot that is not used internally. An
	// implementation may optionally use it to store for example the
	// application name or author information.
	Custom interface{}
}

// TokenCredentials holds the identifier and shared secret used to
// authenticate a resource owner.
type TokenCredentials struct {
	ID       string
	Secret   string
	ClientID string

	// Custom is an extension slot that is not used internally. An
	// implementation may optionally use it to store for example a
	// user association.
	Custom interface{}
}

// WriteTo encodes and writes the identifier and secret to w.
func (t *TokenCredentials) WriteTo(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	v := make(url.Values)
	v.Set("oauth_token", t.ID)
	v.Set("oauth_token_secret", t.Secret)
	_, err := w.Write([]byte(v.Encode()))
	return err
}

// TempCredentials holds the identifier and shared secret used to make an
// authorization request to the resource owner.
type TempCredentials struct {
	ID               string
	Secret           string
	ClientID         string
	Callback         *url.URL
	VerificationCode string

	// Custom is an extension slot that is not used internally. An
	// implementation may optionally use it to store for example a
	// user association.
	Custom interface{}
}

// WriteTo encodes and writes the identifier and secret to w.
func (t *TempCredentials) WriteTo(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	v := make(url.Values)
	v.Set("oauth_token", t.ID)
	v.Set("oauth_token_secret", t.Secret)
	v.Set("oauth_callback_confirmed", "true")
	_, err := w.Write([]byte(v.Encode()))
	return err
}

// Redirect replies with a redirect to the callback URL, with identifier and
// verification code added to the query string. It panics if there is no
// callback.
func (t *TempCredentials) Redirect(w http.ResponseWriter, r *http.Request) {
	if t.Callback == nil {
		panic("missing callback")
	}
	http.Redirect(w, r, t.verifiedCallback(), http.StatusFound)
}

func (t *TempCredentials) verifiedCallback() string {
	u := new(url.URL)
	*u = *t.Callback
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += fmt.Sprintf("%s=%s&%s=%s",
		tokenIdentifier, url.QueryEscape(t.ID),
		verificationCode, url.QueryEscape(t.VerificationCode),
	)
	return u.String()
}

func newToken(c *ClientCredentials) (*TokenCredentials, error) {
	var err error

	t := TokenCredentials{ClientID: c.ID}
	t.ID, err = randHex(16)
	if err != nil {
		return nil, err
	}
	t.Secret, err = randHex(20)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func newTempToken(c *ClientCredentials, callback *url.URL) (*TempCredentials, error) {
	tkn, err := newToken(c)
	if err != nil {
		return nil, err
	}
	t := TempCredentials{
		ID:       tkn.ID,
		Secret:   tkn.Secret,
		ClientID: tkn.ClientID,
		Callback: callback,
	}
	t.VerificationCode, err = randHex(20)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
