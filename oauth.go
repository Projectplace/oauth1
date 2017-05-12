// Package oauth1 provides building blocks for implementing an OAuth 1.0 server.
package oauth1

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
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

	ctxKeyClient = ctxKey("client")
	ctxKeyToken  = ctxKey("token")
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

	Realm          string      // realm to use in WWW-Authenticate headers
	LogClientError func(error) // optional logging function that is called on client error responses
	LogServerError func(error) // optional logging function that is called on server error responses

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

// TempCredentials creates and responds with new temporary credentials.
// These are used by the client to obtain authorization from the resource
// owner.
func (s *Server) TempCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")

	rr, err := s.validate(r, callback)
	if err != nil {
		s.writeError(w, err)
		return
	}
	t, err := newTempToken(rr.client, rr.proto.callback)
	if err == nil {
		err = s.Store.AddToken(r.Context(), t)
	}
	if err != nil {
		s.writeError(w, err)
		return
	}
	res := make(url.Values)
	res.Set("oauth_callback_confirmed", "true")
	res.Set("oauth_token", t.ID)
	res.Set("oauth_token_secret", t.Secret)
	w.Write([]byte(res.Encode()))
}

// Authorize is a middleware that validates requests made by the client to
// obtain authorization from the resource owner. The client and temporary token
// are injected in the context of the request.
//
// If access is granted the underlying handler should redirect the user agent
// to the token's VerifiedCallback() if non-nil or otherwise display the
// token's VerificationCode..
func (s *Server) Authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			s.writeError(w, newBadRequest("bad query", err))
			return
		}
		tid := r.Form.Get(tokenIdentifier)
		if tid == "" {
			s.writeError(w, missingParameter(tokenIdentifier))
			return
		}
		t, err := s.Store.GetToken(r.Context(), tid)
		if err == ErrNotFound || (err == nil && !t.IsTemporary()) {
			err = unauthorized("temporary token not found")
		}
		if err != nil {
			s.writeError(w, err)
			return
		}
		c, err := s.Store.GetClient(r.Context(), t.ClientID)
		if err != nil {
			s.writeError(w, err)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, ctxKeyClient, c)
		ctx = context.WithValue(ctx, ctxKeyToken, t)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TokenCredentials consumes the supplied temporary token credentials and responds
// with new token credentials that can be used by the client for authenticated
// requests.
func (s *Server) TokenCredentials(w http.ResponseWriter, r *http.Request) {
	rr, err := s.validate(r, tokenIdentifier, verificationCode)
	if err != nil {
		s.writeError(w, err)
		return
	}

	var t *TokenCredentials

	if subtle.ConstantTimeCompare([]byte(rr.token.VerificationCode), []byte(rr.proto.verificationCode)) != 1 {
		err = unauthorized("oauth_verifier mismatch")
	} else {
		t, err = convertToken(r.Context(), s.Store, rr.token)
	}
	if err != nil {
		s.writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	v := make(url.Values)
	v.Set("oauth_token", t.ID)
	v.Set("oauth_token_secret", t.Secret)
	w.Write([]byte(v.Encode()))
}

// Authenticate is a middleware that verifies that incoming requests are
// protocol compliant and authentic, and respond with an error if not. Valid
// requests are passed to the underlying handler, with client and token (if
// applicable) injected into the context.
func (s *Server) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			c   *ClientCredentials
			t   *TokenCredentials
			err error
		)

		rr, err := s.validate(r)
		if err != nil {
			s.writeError(w, err)
			return
		}
		c = rr.client
		t = rr.token
		if t != nil && t.IsTemporary() {
			s.writeError(w, unauthorized("temporary token credentials"))
			return
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, ctxKeyClient, c)
		ctx = context.WithValue(ctx, ctxKeyToken, t)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) writeError(w http.ResponseWriter, err error) {
	switch err := errors.Cause(err).(type) {
	case badRequestError:
		if s.LogClientError != nil {
			s.LogClientError(err)
		}
		http.Error(w, fmt.Sprintf("%s: %s", http.StatusText(http.StatusBadRequest), err.msg), http.StatusBadRequest)
	case unauthorized:
		if s.LogClientError != nil {
			s.LogClientError(err)
		}
		if s.Realm != "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`OAuth realm="%s"`, s.Realm))
		}
		http.Error(w, fmt.Sprintf("%s: %s", http.StatusText(http.StatusUnauthorized), err), http.StatusUnauthorized)
	default:
		if s.LogServerError != nil {
			s.LogServerError(err)
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
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
			return nil, unauthorized(fmt.Sprintf("timestamp expired %s ago", d-s.MaxAge))
		case d+s.MaxSkew < 0:
			return nil, newBadRequest(fmt.Sprintf("timestamp set %s in future", -d), errors.New("bad timestamp"))
		}
	}

	rr.client, err = s.Store.GetClient(r.Context(), proto.clientID)
	if err != nil {
		if err == ErrNotFound {
			return rr, unauthorized("client not found")
		}
		return rr, errors.Wrap(err, "failed to fetch client")
	}
	if proto.tokenID != "" {
		rr.token, err = s.Store.GetToken(r.Context(), proto.tokenID)
		if err != nil {
			if err == ErrNotFound {
				return rr, unauthorized("token not found")
			}
			return rr, errors.Wrapf(err, "failed to fetch token %s", proto.tokenID)
		}
		if rr.token.ClientID != proto.clientID {
			return rr, unauthorized("client/token mismatch")
		}
	}

	if !s.skipVerifySignature {
		err = s.verifySignature(rr)
	}

	if err == nil && !s.skipVerifyNonce {
		err = s.Store.ConsumeNonce(r.Context(), proto.nonce, proto.timestamp, proto.clientID, proto.tokenID)
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
		return errors.New("signature mismatch")
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
	var params url.Values
	var err error

	params, err = authorizationHeaderParameters(r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}
	formParams, err := requestBodyParameters(r)
	if err != nil {
		return nil, err
	}
	for k, v := range formParams {
		params[k] = append(params[k], v...)
	}
	for k, v := range r.URL.Query() {
		params[k] = append(params[k], v...)
	}
	return params, nil
}

func authorizationHeaderParameters(s string) (url.Values, error) {
	const scheme = "oauth "
	if len(s) < len(scheme) || strings.ToLower(s[:len(scheme)]) != scheme {
		return nil, nil
	}
	s = s[len(scheme):]

	var err error
	h := make(url.Values)
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
		h.Add(k, v)
	}
	return h, nil
}

func requestBodyParameters(r *http.Request) (params url.Values, err error) {
	switch r.Method {
	case "POST", "PUT", "PATCH":
		// Should we parse GET request bodies as well?
	default:
		return nil, nil
	}

	ct := r.Header.Get("Content-Type")
	ct, _, _ = mime.ParseMediaType(ct)
	if ct != "application/x-www-form-urlencoded" {
		return nil, nil
	}

	// take a peek at the request body
	maxFormSize := int64(10 << 20) // 10 MB is a lot of text.
	buf := new(bytes.Buffer)
	reader := io.LimitReader(io.TeeReader(r.Body, buf), maxFormSize+1)
	defer func() {
		r.Body = struct {
			io.Reader
			io.Closer
		}{
			io.MultiReader(buf, r.Body),
			r.Body,
		}
	}()

	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxFormSize {
		err = newBadRequest("form too large", errors.New(strconv.Itoa(len(b))))
		return nil, err
	}
	params, err = url.ParseQuery(string(b))
	if err != nil {
		err = newBadRequest("bad form", err)
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

// GetToken returns the token credentials from a request context if available.
// If no token is available nil is returned.
func GetToken(ctx context.Context) *TokenCredentials {
	id, _ := ctx.Value(ctxKeyToken).(*TokenCredentials)
	return id
}

// GetClient returns the client credentials from a request context if available.
// If no client is available nil is returned.
func GetClient(ctx context.Context) *ClientCredentials {
	id, _ := ctx.Value(ctxKeyClient).(*ClientCredentials)
	return id
}

var _ http.HandlerFunc = (*Server)(nil).TempCredentials
var _ http.HandlerFunc = (*Server)(nil).TokenCredentials
