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

// Server provides methods for interacting with OAuth 1.0 clients.
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

	// Realm is the description of the protected area to be included in
	// WWW-Authenticate headers.
	//
	// If Realm is empty WWW-Authenticate headers are suppressed.
	Realm string

	// used for testing only
	time                *clock
	skipVerifySignature bool
	skipVerifyNonce     bool
}

// Store is the interface used to manage credentials and nonces.
type Store interface {
	// GetClient loads the credentials with the given ID from the database.
	// It returns ErrNotFound if no matching record can be found.
	GetClient(ctx context.Context, id string) (*ClientCredentials, error)

	// GetToken loads the token credentials with the given ID from the
	// database. It returns ErrNotFound if no matching record can be found.
	GetToken(ctx context.Context, id string) (*TokenCredentials, error)

	// GetToken loads the temporary credentials with the given ID from the
	// database. It returns ErrNotFound if no matching record can be found.
	GetTemp(ctx context.Context, id string) (*TempCredentials, error)

	// AddTempCredentials adds new temporary credentials to the database.
	AddTempCredentials(context.Context, *TempCredentials) error

	// ConvertTempCredentials replaces the temporary credentials with token
	// credentials.
	ConvertTempCredentials(ctx context.Context, old *TempCredentials, new *TokenCredentials) error

	// ConsumeNonce validates that a nonce is unique across all requests with
	// the same timestamp, client and token combinations. If the combination
	// has been used before ConsumeNonce returns ErrNonceAlreadyUsed.
	ConsumeNonce(ctx context.Context, nonce string, timestamp time.Time, clientID, tokenID string) error
}

// InitiateAuthorization validates a request for new temporary credentials and
// creates them if successful.
//
// This is the first step taken by a client to acquire token credentials.
func (s *Server) InitiateAuthorization(r *http.Request) (*TempCredentials, error) {
	required := []string{callback}
	if s.FixedCallbacks {
		// RFC 5849 states that oauth_callback must be set to "oob" if the
		// callback URI has been established by other means, but it doesn't
		// seem necessary to enforce this.
		required = nil
	}
	rr, err := s.validate(r, false, required...)
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
	return t, s.Store.AddTempCredentials(r.Context(), t)
}

// RequestAuthorization validates a request made by the client to obtain
// authorization from the resource owner.
//
// The service provider must ask the resource owner to grant access,
// and if authorization is given the user agent should be redirected
// to the token's VerifiedCallback(). If this callback is nil the
// VerificationCode should instead be displayed together with instructions
// to manually inform the client that authorization is completed.
//
// This is the second step for a client to acquire token credentials.
func (s *Server) RequestAuthorization(r *http.Request) (*ClientCredentials, *TempCredentials, error) {
	tid := r.URL.Query().Get(tokenIdentifier)
	if tid == "" {
		return nil, nil, missingParameter(tokenIdentifier)
	}
	t, err := s.getTemp(r.Context(), tid)
	if err != nil {
		return nil, nil, err
	}
	c, err := s.getClient(r.Context(), t.ClientID)
	if err != nil {
		return nil, nil, err
	}

	return c, t, nil
}

// ConcludeAuthorization consumes the supplied temporary token credentials
// and returns new token credentials that can be used by the client for
// authenticated requests.
//
// This is the third and final step for a client to acquire token credentials.
func (s *Server) ConcludeAuthorization(r *http.Request) (*TokenCredentials, error) {
	rr, err := s.validate(r, true, tokenIdentifier, verificationCode)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(rr.temp.VerificationCode), []byte(rr.proto.verificationCode)) != 1 {
		return nil, unauthorized{"oauth_verifier mismatch", s.Realm}
	}

	t, err := newToken(rr.client)
	if err != nil {
		return nil, errors.Wrap(err, "could not create token")
	}
	t.Custom = rr.temp.Custom
	err = s.Store.ConvertTempCredentials(r.Context(), rr.temp, t)
	if err == ErrNotFound {
		return nil, unauthorized{"temporary credentials not found", s.Realm}
	}

	return t, err
}

// Authenticate verifies that the authenticated request is protocol compliant
// and valid. The *TokenCredentials returned is nil if the request is signed
// with only client credentials.
func (s *Server) Authenticate(r *http.Request) (*ClientCredentials, *TokenCredentials, error) {
	var (
		c   *ClientCredentials
		t   *TokenCredentials
		err error
	)

	rr, err := s.validate(r, false)
	if err != nil {
		return nil, nil, err
	}
	c = rr.client
	t = rr.token
	return c, t, nil
}

type request struct {
	*http.Request
	rawProto url.Values // oauth protocol parameters
	proto    *protocolParameters

	client *ClientCredentials
	token  *TokenCredentials
	temp   *TempCredentials
}

// validate checks that the request is spec compliant and authentic.
func (s *Server) validate(r *http.Request, temp bool, required ...string) (*request, error) {
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

	if s.MaxAge > 0 {
		if dt := s.time.Since(proto.timestamp); dt > s.MaxAge+s.MaxSkew {
			return nil, unauthorized{fmt.Sprintf("timestamp expired %s ago", dt), s.Realm}
		}
		if dt := s.time.Until(proto.timestamp); dt > s.MaxSkew {
			return nil, newBadRequest(fmt.Sprintf("timestamp set %s in future", dt), errors.New("bad timestamp"))
		}
	}

	rr.client, err = s.getClient(r.Context(), proto.clientID)
	if err != nil {
		return rr, err
	}

	if temp {
		rr.temp, err = s.getTemp(r.Context(), proto.tokenID)
	} else if proto.tokenID != "" {
		rr.token, err = s.getToken(r.Context(), proto.tokenID)
	}

	if err != nil {
		return rr, err
	}
	if rr.token != nil && rr.token.ClientID != proto.clientID {
		return rr, unauthorized{"client/token mismatch", s.Realm}
	}
	if rr.temp != nil && rr.temp.ClientID != proto.clientID {
		return rr, unauthorized{"client/token mismatch", s.Realm}
	}

	if !s.skipVerifySignature {
		err = errors.Wrap(s.verifySignature(rr), "invalid signature")
	}

	if err == nil && !s.skipVerifyNonce {
		err = s.Store.ConsumeNonce(r.Context(), proto.nonce, proto.timestamp, proto.clientID, proto.tokenID)
		if err == ErrNonceAlreadyUsed {
			return rr, unauthorized{"nonce already used", s.Realm}
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
	} else if r.temp != nil {
		key += encode(r.temp.Secret)
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
	return []byte(encode(strings.ToUpper(r.Method)) + "&" + encode(baseStringURI(r.Request)) + "&" + encode(normalize(r.rawProto)))
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

func (s *Server) getClient(ctx context.Context, id string) (*ClientCredentials, error) {
	c, err := s.Store.GetClient(ctx, id)
	if err == ErrNotFound {
		return nil, unauthorized{"client credentials not found", s.Realm}
	}
	return c, errors.Wrapf(err, "failed to fetch client %s", id)
}

func (s *Server) getToken(ctx context.Context, id string) (*TokenCredentials, error) {
	t, err := s.Store.GetToken(ctx, id)
	if err == ErrNotFound {
		return nil, unauthorized{"token credentials not found", s.Realm}
	}
	return t, errors.Wrapf(err, "failed to fetch token %s", id)
}

func (s *Server) getTemp(ctx context.Context, id string) (*TempCredentials, error) {
	t, err := s.Store.GetTemp(ctx, id)
	if err == ErrNotFound {
		return nil, unauthorized{"temporary credentials not found", s.Realm}
	}
	return t, errors.Wrapf(err, "failed to fetch temporary credentials %s", id)
}

type clock time.Time

func (c *clock) Since(t time.Time) time.Duration {
	if c == nil {
		return time.Since(t)
	}
	return time.Time(*c).Sub(t)
}

func (c *clock) Until(t time.Time) time.Duration {
	if c == nil {
		return time.Until(t)
	}
	return t.Sub(time.Time(*c))
}
