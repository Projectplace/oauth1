// Package oauth1 provides building blocks for implementing an OAuth 1.0 server.
package oauth1

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/pkg/errors"
)

const (
	clientIdentifier = "oauth_consumer_key"
	signatureMethod  = "oauth_signature_method"
	timestamp        = "oauth_timestamp"
	nonce            = "oauth_nonce"
	signature        = "oauth_signature"
	version          = "oauth_version"
	callback         = "oauth_callback"
	tokenIdentifier  = "oauth_token"
	verificationCode = "oauth_verifier"
)

type ctxKey string

// Server provides methods for interacting with oauth 1.0 clients.
type Server struct {
	// Store is the database used to store credentials and nonces.
	Store Store

	// MaxAge specifies an age limit for timestamps, after (optionally)
	// accounting for clock skew. A request with an older timestamp will be
	// denied with HTTP 401 Unauthorized.
	//
	// A MaxAge of zero means no limit.
	MaxAge time.Duration

	// MaxSkew specifies the allowed difference between client and server time.
	//
	// It is only applied if MaxAge is not zero.
	MaxSkew time.Duration

	// FixedCallbacks controls if the callback URL should be specified via the
	// oauth_callback protocol parameter or pre-configured per client.
	FixedCallbacks bool

	Realm string // realm to use in WWW-Authenticate headers

	// used for testing only
	clock               *clock
	skipVerifySignature bool
	skipVerifyNonce     bool
}

// Store is the interface used to manage credentials and nonces.
type Store interface {
	// GetClient reads the credentials with the given ID from the database.
	// ErrNotFound is returned if no matching record can be found.
	GetClient(ctx context.Context, id string) (*ClientCredentials, error)

	// AddToken adds a new token to the database. The ID may optionally be
	// changed prior to persisting the credentials.
	AddToken(ctx context.Context, t *TokenCredentials) error

	// GetToken reads the credentials with the given ID from the database.
	// ErrNotFound is returned if no matching record can be found.
	GetToken(ctx context.Context, id string) (*TokenCredentials, error)

	// ReplaceToken deletes the old token credentials and adds the new ones.
	// If no matching record can be found ErrNotFound is returned.
	ReplaceToken(ctx context.Context, old, new *TokenCredentials) error

	// ConsumeNonce returns ErrAlreadyExists if the nonce is not unique to the
	// timestamp, client and token combination.
	ConsumeNonce(ctx context.Context, nonce string, timestamp time.Time, clientID string, tokenID string) error
}

// TempCredentials creates new temporary credentials. These are used by the
// client to obtain authorization from the resource owner.
func (s *Server) TempCredentials(r *http.Request) (*TokenCredentials, error) {
	required := []string{callback}
	if s.FixedCallbacks {
		// RFC 5849 states that oauth_callback must be set to "oob" if the
		// callback URI has been established by other means, but it doesn't
		// seem necessary to enforce this.
		required = nil
	}
	rr, err := s.validate(r, required...)
	if err != nil {
		return nil, err
	}
	callback := rr.proto.callback
	if s.FixedCallbacks {
		callback = rr.client.Callback
	}
	t, err := newTempToken(rr.client, callback)
	if err != nil {
		return nil, err
	}
	return t, s.Store.AddToken(r.Context(), t)
}

// Authorize validates a request made by the client to obtain authorization
// from the resource owner.
//
// If access is granted the service provider should redirect the user agent to
// the token's VerifiedCallback(). If the callback is nil the VerificationCode
// can be displayed to the user in some other manner.
func (s *Server) Authorize(r *http.Request) (*ClientCredentials, *TokenCredentials, error) {
	tid := r.URL.Query().Get(tokenIdentifier)
	if tid == "" {
		return nil, nil, missingParameter(tokenIdentifier)
	}
	t, err := s.Store.GetToken(r.Context(), tid)
	if err == ErrNotFound || (err == nil && !t.IsTemporary()) {
		err = unauthorized{"temporary token not found", s.Realm}
	}
	if err != nil {
		return nil, nil, err
	}
	c, err := s.Store.GetClient(r.Context(), t.ClientID)
	if err != nil {
		return nil, nil, err
	}

	return c, t, nil
}

// TokenCredentials consumes the supplied temporary token credentials and
// returns new token credentials that can be used by the client for
// authenticated requests.
func (s *Server) TokenCredentials(r *http.Request) (*TokenCredentials, error) {
	rr, err := s.validate(r, tokenIdentifier, verificationCode)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(rr.token.VerificationCode), []byte(rr.proto.verificationCode)) != 1 {
		return nil, unauthorized{"oauth_verifier mismatch", s.Realm}
	}
	return convertToken(r.Context(), s.Store, rr.token)
}

// WriteToken is used to respond to a request for temporary credentials or
// token credentials.
func WriteToken(w http.ResponseWriter, t *TokenCredentials) {
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	v := make(url.Values)
	v.Set("oauth_token", t.ID)
	v.Set("oauth_token_secret", t.Secret)
	if t.IsTemporary() {
		v.Set("oauth_callback_confirmed", "true")
	}
	w.Write([]byte(v.Encode()))
}

// Authenticate verifies that the authenticated request is protocol compliant and valid.
func (s *Server) Authenticate(r *http.Request) (*ClientCredentials, *TokenCredentials, error) {
	var (
		c   *ClientCredentials
		t   *TokenCredentials
		err error
	)

	rr, err := s.validate(r)
	if err != nil {
		return nil, nil, err
	}
	c = rr.client
	t = rr.token
	if t != nil && t.IsTemporary() {
		return nil, nil, unauthorized{"temporary token credentials", s.Realm}
	}
	return c, t, nil
}

type request struct {
	*http.Request
	rawProto url.Values // oauth protocol parameters
	proto    *protocolParameters

	client *ClientCredentials
	token  *TokenCredentials
}

// validate checks that the request is spec compliant and authentic.
func (s *Server) validate(r *http.Request, required ...string) (*request, error) {
	params, err := requestParameters(r)
	if err != nil {
		return nil, errors.Wrap(err, "bad request parameters")
	}
	var skipKeys []string
	if s.skipVerifySignature {
		skipKeys = append(skipKeys, signature)
	}
	if s.skipVerifyNonce {
		skipKeys = append(skipKeys, nonce)
	}
	proto, err := newProtocolParameters(params, required, skipKeys)
	if err != nil {
		return nil, errors.Wrap(err, "bad protocol parameters")
	}

	rr := &request{Request: r, rawProto: params, proto: proto}

	if s.MaxSkew > 0 {
		switch d := s.clock.Now().Sub(proto.timestamp); {
		case d-s.MaxSkew > s.MaxAge:
			return nil, unauthorized{fmt.Sprintf("timestamp expired %s ago", d-s.MaxAge), s.Realm}
		case d+s.MaxSkew < 0:
			return nil, newBadRequest(fmt.Sprintf("timestamp set %s in future", -d), errors.New("bad timestamp"))
		}
	}

	rr.client, err = s.Store.GetClient(r.Context(), proto.clientID)
	if err != nil {
		if err == ErrNotFound {
			return rr, unauthorized{"client not found", s.Realm}
		}
		return rr, errors.Wrap(err, "failed to fetch client")
	}
	if proto.tokenID != "" {
		rr.token, err = s.Store.GetToken(r.Context(), proto.tokenID)
		if err != nil {
			if err == ErrNotFound {
				return rr, unauthorized{"token not found", s.Realm}
			}
			return rr, errors.Wrapf(err, "failed to fetch token %s", proto.tokenID)
		}
		if rr.token.ClientID != proto.clientID {
			return rr, unauthorized{"client/token mismatch", s.Realm}
		}
	}

	if !s.skipVerifySignature {
		err = errors.Wrap(s.verifySignature(rr), "invalid signature")
	}

	if err == nil && !s.skipVerifyNonce {
		err = s.Store.ConsumeNonce(r.Context(), proto.nonce, proto.timestamp, proto.clientID, proto.tokenID)
		if err == ErrNonceAlreadyUsed {
			err = unauthorized{"nonce already used", s.Realm}
		}
		err = errors.Wrap(err, "failed to verify nonce")
	}
	return rr, err
}

func (s *Server) verifySignature(r *request) error {
	key := ""
	if r.client != nil {
		key += encode(r.client.Secret)
	}
	key += "&"
	if r.token != nil {
		key += encode(r.token.Secret)
	}
	mac := hmac.New(sha1.New, []byte(key))
	_, err := mac.Write([]byte(baseString(r)))
	if err != nil {
		return err
	}
	if !hmac.Equal(r.proto.signature, mac.Sum(nil)) {
		return unauthorized{"signature mismatch", s.Realm}
	}
	return nil
}

// parameters used in incoming requests
type protocolParameters struct {
	// required parameters
	timestamp time.Time
	nonce     string
	signature []byte

	// optional parameters
	clientID         string
	tokenID          string
	callback         *url.URL
	verificationCode string
}

// Verify that the protocol parameters are well formed.
func newProtocolParameters(p url.Values, extraReq, skipReq []string) (*protocolParameters, error) {
	keys := map[string]bool{
		clientIdentifier: true,
		signatureMethod:  true,
		timestamp:        true,
		nonce:            true,
		signature:        true,

		version:          false,
		callback:         false,
		tokenIdentifier:  false,
		verificationCode: false,
	}
	for _, k := range extraReq {
		keys[k] = true
	}
	for _, k := range skipReq {
		keys[k] = false
	}

	for k, required := range keys {
		switch vs := p[k]; len(vs) {
		case 0:
			if required {
				return nil, missingParameter(k)
			}
		case 1:
			if len(vs[0]) == 0 {
				return nil, badValue(k, errors.New("empty string"))
			}
			continue
		default:
			return nil, newBadRequest(fmt.Sprintf("multiple values for %v parameter", k), fmt.Errorf("%#v", vs))
		}
	}
	if v := p.Get(version); v != "" && v != "1.0" {
		err := badValue(version, errors.New(strconv.Quote(v)))
		err.msg += ": only version 1.0 supported"
		return nil, err
	}
	if v := p.Get(signatureMethod); v != "HMAC-SHA1" {
		err := badValue(signatureMethod, errors.New(strconv.Quote(v)))
		err.msg += ": only HMAC-SHA1 supported"
		return nil, err
	}

	var err error

	pp := new(protocolParameters)
	pp.nonce = p.Get(nonce)
	pp.clientID = p.Get(clientIdentifier)
	pp.tokenID = p.Get(tokenIdentifier)
	pp.verificationCode = p.Get(verificationCode)

	ts, err := strconv.ParseInt(p.Get(timestamp), 10, 64)
	if err != nil {
		return nil, badValue(timestamp, err)
	}
	pp.timestamp = time.Unix(ts, 0)

	pp.signature, err = base64.StdEncoding.DecodeString(p.Get(signature))
	if err != nil {
		return nil, badValue(signature, err)
	}

	if s := p.Get(callback); s != "" && s != "oob" {
		pp.callback, err = url.Parse(s)
		if err != nil {
			return nil, badValue(callback, err)
		}
		if pp.callback.Host == "" {
			err := badValue(callback, fmt.Errorf("%s not absolute", pp.callback))
			err.msg += ": URI not absolute"
			return nil, err
		}
	}

	return pp, nil
}

func baseString(r *request) []byte {
	return []byte(fmt.Sprintf("%s&%s&%s", encode(strings.ToUpper(r.Method)), encode(baseStringURI(r.Request)), encode(normalize(r.rawProto))))
}

func baseStringURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if r.Header.Get("X-Forwarded-Proto") != "" {
		scheme = r.Header.Get("X-Forwarded-Proto")
	}
	authority := r.Host
	if host, port, err := net.SplitHostPort(r.Host); err == nil {
		switch {
		case port == "80" && scheme == "http":
			authority = host
		case port == "443" && scheme == "https":
			authority = host
		}
	}
	authority = strings.ToLower(authority)

	return fmt.Sprintf("%s://%s%s", scheme, authority, r.URL.EscapedPath())
}

// normalize the request parameters according to §3.4.1.3.2.
func normalize(params url.Values) string {
	n := 0
	for k, vs := range params {
		if k == "oauth_signature" {
			continue
		}
		n += len(vs)
	}

	s := make([]string, 0, n)

	for k, vs := range params {
		if k == "oauth_signature" {
			continue
		}
		for _, v := range vs {
			// NULL is used instead of = so sorting will work
			s = append(s, encode(k)+"\x00"+encode(v))
		}
	}
	sort.Strings(s)
	bs := strings.Join(s, "&")
	return strings.Replace(bs, "\x00", "=", -1)
}

func requestParameters(r *http.Request) (url.Values, error) {
	params, err := authorizationHeaderParameters(r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}
	err = r.ParseForm()
	if err != nil {
		return nil, badRequestError{err, "bad form"}
	}
	for k, v := range r.Form {
		params[k] = append(params[k], v...)
	}
	return params, nil
}

func authorizationHeaderParameters(s string) (params url.Values, err error) {
	params = make(url.Values)
	const scheme = "oauth "
	if len(s) < len(scheme) || strings.ToLower(s[:len(scheme)]) != scheme {
		return params, err
	}
	s = s[len(scheme):]

	for _, chunk := range strings.Split(s, ",") {
		chunk = strings.TrimLeftFunc(chunk, unicode.IsSpace)
		if strings.HasPrefix(chunk, "realm=") {
			continue
		}
		i := strings.Index(chunk, "=")
		if i < 0 {
			return nil, newBadRequest("bad authorization header", fmt.Errorf(`missing "=" in %#v`, chunk))
		}
		k, v := chunk[:i], chunk[i+1:]
		if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
			return nil, newBadRequest("bad authorization header", fmt.Errorf(`missing surrounding quotes in %#v`, chunk))
		}
		v, err = url.PathUnescape(v[1 : len(v)-1])
		if err != nil {
			return nil, newBadRequest("bad authorization header", fmt.Errorf("bad value %#v: %v", v, err))
		}
		params.Add(k, v)
	}
	return params, err
}

type clock time.Time

func (c *clock) Now() time.Time {
	if c == nil {
		return time.Now()
	}
	return time.Time(*c)
}
