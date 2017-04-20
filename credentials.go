package oauth1

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
)

// ClientCredentials holds the identifier and shared secret used to
// authenticate a particular client.
type ClientCredentials struct {
	ID     string
	Secret string

	// Custom is an extension slot that is not used internally. A caller may
	// optionally use it to store for example application name or author
	// information.
	Custom interface{} // custom data
}

// TokenCredentials holds the identifier and shared secret used to
// authenticate a resource owner.
type TokenCredentials struct {
	ID       string
	Secret   string
	ClientID string

	// for use with temporary credentials
	Callback         *url.URL
	VerificationCode string

	// Custom is an extension slot that is not used internally. A caller may
	// optionally use it to store for example a user association.
	Custom interface{} // custom data
}

// VerifiedCallback returns callback URL with oauth_token and
// oauth_verifier parameters appended to the query string.
func (t *TokenCredentials) VerifiedCallback() *url.URL {
	if t.Callback == nil {
		return nil
	}
	u := new(url.URL)
	*u = *t.Callback
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += fmt.Sprintf("%s=%s&%s=%s",
		tokenIdentifier, url.QueryEscape(t.ID),
		verificationCode, url.QueryEscape(t.VerificationCode),
	)
	return u
}

// IsTemporary returns true for temporary credentials.
func (t *TokenCredentials) IsTemporary() bool {
	return t.VerificationCode != ""
}

func newToken(c *ClientCredentials) (*TokenCredentials, error) {
	var err error

	t := new(TokenCredentials)
	if c != nil {
		t.ClientID = c.ID
	}
	t.ID, err = randHex(16)
	if err != nil {
		return nil, err
	}
	t.Secret, err = randHex(20)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func newTempToken(c *ClientCredentials, callback *url.URL) (*TokenCredentials, error) {
	t, err := newToken(c)
	if err != nil {
		return nil, err
	}
	t.Callback = callback
	t.VerificationCode, err = randHex(20)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func convertToken(ctx context.Context, db Store, old *TokenCredentials) (*TokenCredentials, error) {
	c, err := db.GetClient(ctx, old.ClientID)
	if err != nil {
		return nil, err
	}
	new, err := newToken(c)
	if err != nil {
		return nil, err
	}
	err = db.ReplaceToken(ctx, old, new)
	return new, err
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
