package oauth1

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
)

var (
	printerClient = &ClientCredentials{
		ID:     "dpf43f3p2l4k3l03",
		Secret: "kd94hf93k423kf44",
	}
	tempToken = &TokenCredentials{
		ID:               "hh5s93j4hdidpola",
		Secret:           "hdhd0244k9j7ao03",
		ClientID:         printerClient.ID,
		Callback:         mustParseURL("http://printer.example.com/ready"),
		VerificationCode: "hfdp7dh39dks9884",
	}
	photoToken = &TokenCredentials{
		ID:       "nnch734d00sl2jdk",
		Secret:   "pfkkdhi9sl3r4s00",
		ClientID: printerClient.ID,
	}
	unrelatedToken = &TokenCredentials{
		ID:       "unrelated",
		Secret:   "xxx",
		ClientID: "unrelated",
	}
	unrelatedTempToken = &TokenCredentials{
		ID:               "foo",
		Secret:           "bar",
		ClientID:         printerClient.ID,
		Callback:         mustParseURL("http://cliche.example.com/verify?oh=yeah"),
		VerificationCode: "secret",
	}
)

func TestAuthenticate(t *testing.T) {
	server := newTestServer()

	testCases := []struct {
		name       string
		request    string
		wantClient *ClientCredentials
		wantToken  *TokenCredentials
		wantCode   int
	}{
		{
			"rfc example",
			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="nnch734d00sl2jdk",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131202"` +
				"\r\n\r\n",
			printerClient,
			photoToken,
			http.StatusOK,
		},
		{
			"temp token",
			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="hh5s93j4hdidpola",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131202"` +
				"\r\n\r\n",
			nil,
			nil,
			http.StatusUnauthorized,
		},
		{
			"missing token",
			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131202"` +
				"\r\n\r\n",
			printerClient,
			nil,
			http.StatusOK,
		},
		{
			"invalid token",
			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="aaaaaaaaaaaaaaaa",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131202"` +
				"\r\n\r\n",
			nil,
			nil,
			http.StatusUnauthorized,
		},
		{
			"missing consumer_key",
			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_token="nnch734d00sl2jdk",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131202"` +
				"\r\n\r\n",
			nil,
			nil,
			http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := readRequest(tc.request, true)
			cli, tkn, err := server.Authenticate(r)

			if code := errCode(err); code != tc.wantCode {
				t.Logf("client %v; token %v", cli, tkn)
				t.Fatalf("want status %d; error `%v` would result in status %d", tc.wantCode, err, code)
			}
			if !cli.is(tc.wantClient) {
				t.Errorf("want client %v; got %v", tc.wantClient, cli)
			}
			if !tkn.is(tc.wantToken) {
				t.Errorf("want token %v; got %v", tc.wantToken, tkn)
			}
		})
	}
}

func TestTokenCredentials(t *testing.T) {
	server := newTestServer()

	testCases := []struct {
		name    string
		request string
		wantErr error
	}{
		{
			"rfc example",
			"POST /token HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="hh5s93j4hdidpola",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131201",` +
				` oauth_verifier="hfdp7dh39dks9884",` +
				` oauth_signature="gKgrFCywp7rO0OXSjdot%2FIHF7IU%3D"` +
				"\r\n\r\n",
			nil,
		},
		{
			"missing oauth_token",
			"POST /token HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131201",` +
				` oauth_verifier="secret",` +
				` oauth_signature="gKgrFCywp7rO0OXSjdot%2FIHF7IU%3D"` +
				"\r\n\r\n",
			missingParameter("oauth_token"),
		},
		{
			"missing oauth_verifier",
			"POST /token HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="foo",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131201",` +
				` oauth_signature="gKgrFCywp7rO0OXSjdot%2FIHF7IU%3D"` +
				"\r\n\r\n",
			missingParameter("oauth_verifier"),
		},
		{
			"invalid oauth_verifier",
			"POST /token HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="foo",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131201",` +
				` oauth_verifier="baz",` +
				` oauth_signature="gKgrFCywp7rO0OXSjdot%2FIHF7IU%3D"` +
				"\r\n\r\n",
			unauthorized{"oauth_verifier mismatch", ""},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := readRequest(tc.request, true)
			tkn, err := server.TokenCredentials(r)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("want error `%v`; got ok", tc.wantErr)
				}
				if err := errors.Cause(err); err.Error() != tc.wantErr.Error() {
					t.Fatalf("want error caused by `%v`; got error caused by `%v`", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("got unexpected error `%v`", err)
			}

			if tkn.IsTemporary() {
				t.Error("got temporary credentials")
			}
			if tkn.ID == "" {
				t.Error("ID missing from token credentials")
			}
			if tkn.Secret == "" {
				t.Error("Secret missing from token credentials")
			}
		})
	}
}

func TestAuthorize(t *testing.T) {
	server := newTestServer()
	server.skipVerifySignature = false
	server.skipVerifyNonce = false

	testCases := []struct {
		name       string
		url        string
		wantClient *ClientCredentials
		wantToken  *TokenCredentials
		wantCode   int
	}{
		{
			"rfc example",
			"https://photos.example.net/authorize?oauth_token=hh5s93j4hdidpola",
			printerClient,
			tempToken,
			http.StatusOK,
		},
		{
			"missing token parameter",
			"https://photos.example.net/authorize",
			nil,
			nil,
			http.StatusBadRequest,
		},
		{
			"invalid token parameter",
			"https://photos.example.net/authorize?oauth_token=aaaaaaaaaaaaaaaa",
			nil,
			nil,
			http.StatusUnauthorized,
		},
		{
			"non-temporary token",
			"https://photos.example.net/authorize?oauth_token=nnch734d00sl2jdk",
			nil,
			nil,
			http.StatusUnauthorized,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			r := httptest.NewRequest("GET", tc.url, nil)
			cli, tkn, err := server.Authorize(r)

			if code := errCode(err); code != tc.wantCode {
				t.Logf("client %v; token %v", cli, tkn)
				t.Fatalf("want status %d; error `%v` would result in status %d", tc.wantCode, err, code)
			}
			if !cli.is(tc.wantClient) {
				t.Errorf("want client %v; got %v", tc.wantClient, cli)
			}
			if !tkn.is(tc.wantToken) {
				t.Errorf("want token %v; got %v", tc.wantToken, tkn)
			}
		})
	}
}

func TestTempCredentials(t *testing.T) {
	var (
		callbackRequired = false
		callbackOptional = true
	)

	server := newTestServer()
	testCases := []struct {
		name           string
		request        string
		fixedCallbacks bool

		wantErr error
	}{
		{
			"rfc example",
			"POST /initiate HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131200",` +
				` oauth_nonce="wIjqoS",` +
				` oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready",` +
				` oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"` +
				"\r\n\r\n",
			callbackRequired,
			nil,
		},
		{
			"missing callback",
			"POST /initiate HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131200",` +
				` oauth_nonce="wIjqoS",` +
				` oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"` +
				"\r\n\r\n",
			callbackRequired,
			missingParameter("oauth_callback"),
		},
		{
			"missing but irrelevant callback",
			"POST /initiate HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131200",` +
				` oauth_nonce="wIjqoS",` +
				` oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"` +
				"\r\n\r\n",
			callbackOptional,
			nil,
		},
		{
			"no oauth_consumer_key",
			"POST /initiate HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131200",` +
				` oauth_nonce="wIjqoS",` +
				` oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready",` +
				` oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"` +
				"\r\n\r\n",
			callbackRequired,
			missingParameter("oauth_consumer_key"),
		},
	}

	var (
		r   *http.Request
		err error
	)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server.FixedCallbacks = tc.fixedCallbacks
			r, err = readRequest(tc.request, true)

			if err != nil {
				t.Fatal(err)
			}
			tkn, err := server.TempCredentials(r)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("want error `%v`; got ok", tc.wantErr)
				}
				if err := errors.Cause(err); err.Error() != tc.wantErr.Error() {
					t.Fatalf("want error caused by `%v`; got error caused by `%v`", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("got unexpected error `%v`", err)
			}

			if !tkn.IsTemporary() {
				t.Error("got non-temporary credentials")
			}
			if tkn.ID == "" {
				t.Error("ID missing from temporary credentials")
			}
			if tkn.Secret == "" {
				t.Error("Secret missing from temporary credentials")
			}
		})
	}
}

func TestWriteToken(t *testing.T) {
	testCases := []struct {
		name        string
		isTemporary bool
	}{
		{"temp credentials", true},
		{"token credentials", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tkn := &TokenCredentials{ID: "123", Secret: "abc"}
			if tc.isTemporary {
				tkn.VerificationCode = "xyz"
			}

			w := httptest.NewRecorder()
			WriteToken(w, tkn)

			if ct := w.HeaderMap.Get("content-type"); ct != "application/x-www-form-urlencoded" {
				t.Errorf("bad content-type: %#v", ct)
			}
			values, err := url.ParseQuery(w.Body.String())
			if err != nil {
				t.Fatal(err)
			}

			if tc.isTemporary {
				if v := values.Get("oauth_callback_confirmed"); v != "true" {
					t.Errorf(`want oauth_callback_confirmed="true"; got %#v`, v)
				}
			}

			for _, k := range []string{"oauth_token", "oauth_token_secret"} {
				if values.Get(k) == "" {
					t.Errorf("missing value for %v", k)
				}
			}
		})

	}
}

func Test_validate(t *testing.T) {
	server := newTestServer()
	server.skipVerifySignature = false

	http, https := false, true
	verifySignature, noVerifySignature := false, true

	testCases := []struct {
		name       string
		request    string
		https      bool // use https instead of http
		skipVerify bool // skip signature verification

		wantClient *ClientCredentials
		wantToken  *TokenCredentials
		wantError  bool
	}{
		{
			"temporarary credentials request",

			"POST /initiate HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131200",` +
				` oauth_nonce="wIjqoS",` +
				` oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready",` +
				` oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"` +
				"\r\n\r\n",
			https,
			verifySignature,

			printerClient,
			nil,
			false,
		},
		{
			"token credentials request",

			"POST /token HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="hh5s93j4hdidpola",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131201",` +
				` oauth_nonce="walatlh",` +
				` oauth_verifier="hfdp7dh39dks9884",` +
				` oauth_signature="gKgrFCywp7rO0OXSjdot%2FIHF7IU%3D"` +
				"\r\n\r\n",
			https,
			verifySignature,

			printerClient,
			tempToken,
			false,
		},
		{
			"authenticated request",

			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="nnch734d00sl2jdk",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131202",` +
				` oauth_nonce="chapoH",` +
				` oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"` +
				"\r\n\r\n",
			http,
			verifySignature,

			printerClient,
			photoToken,
			false,
		},

		// bad requests
		{
			"authenticated request with bad signature",

			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="nnch734d00sl2jdk",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131202",` +
				` oauth_nonce="chapoH",` +
				` oauth_signature="AAAAAAAAAAAAAAAAAAAAAAAAAAA%3D"` +
				"\r\n\r\n",
			http,
			verifySignature,

			nil,
			nil,
			true,
		},
		{
			"timestamp too old",

			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="nnch734d00sl2jdk",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137130899",` +
				` oauth_nonce="chapoH",` +
				` oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"` +
				"\r\n\r\n",
			http,
			noVerifySignature,

			printerClient,
			photoToken,
			true,
		},
		{
			"timestamp in future",

			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="nnch734d00sl2jdk",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131801",` +
				` oauth_nonce="chapoH",` +
				` oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"` +
				"\r\n\r\n",
			http,
			noVerifySignature,

			printerClient,
			photoToken,
			true,
		},
		{
			"token client mismatch",

			"GET /photos?file=vacation.jpg&size=original HTTP/1.1\r\n" +
				"Host: photos.example.net\r\n" +
				`Authorization: OAuth realm="Photos",` +
				` oauth_consumer_key="dpf43f3p2l4k3l03",` +
				` oauth_token="unrelated",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131202",` +
				` oauth_nonce="chapoH",` +
				` oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"` +
				"\r\n\r\n",
			http,
			noVerifySignature,

			printerClient,
			unrelatedToken,
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := readRequest(tc.request, tc.https)
			if err != nil {
				t.Fatal(err)
			}
			server.skipVerifySignature = tc.skipVerify
			r, err := server.validate(req)
			if tc.wantError {
				if err == nil {
					t.Fatal("want error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(r.client, tc.wantClient) {
					t.Errorf("want %#v; got %#v", tc.wantClient, r.client)
				}
				if !reflect.DeepEqual(r.token, tc.wantToken) {
					t.Errorf("want %#v; got %#v", tc.wantToken, r.token)
				}
			}
		})
	}

	server.skipVerifyNonce = false
	t.Run("replay attack", func(t *testing.T) {
		for _, tc := range testCases {
			if tc.wantError {
				continue
			}
			t.Run(tc.name, func(t *testing.T) {
				req, err := readRequest(tc.request, tc.https)
				if err != nil {
					t.Fatal(err)
				}
				server.skipVerifySignature = tc.skipVerify
				_, err = server.validate(req)
				if err != nil {
					t.Fatal("first try:", err)
				}
				_, err = server.validate(req)
				if err == nil {
					t.Fatal("want error")
				}
			})
		}
	})
}

func Test_newProtocolParameters(t *testing.T) {
	testCases := []struct {
		name     string
		params   url.Values
		required []string
		want     *protocolParameters
	}{
		{
			"well-formed authenticated request",
			url.Values{
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"foobar"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
			nil,
			&protocolParameters{
				clientID:  "9djdj82h48djs9d2",
				nonce:     "foobar",
				timestamp: time.Unix(137131201, 0),
				tokenID:   "kkk9d7dh3k39sjv7",
				signature: []byte{118, 58, 44, 36, 160, 202, 37, 32, 252, 239, 141, 246, 227, 127, 227, 118, 77, 247, 146, 86},
			},
		},
		{
			"version 1.0",
			url.Values{
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"foobar"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
				"oauth_version":          []string{"1.0"},
			},
			nil,
			&protocolParameters{
				clientID:  "9djdj82h48djs9d2",
				nonce:     "foobar",
				timestamp: time.Unix(137131201, 0),
				tokenID:   "kkk9d7dh3k39sjv7",
				signature: []byte{118, 58, 44, 36, 160, 202, 37, 32, 252, 239, 141, 246, 227, 127, 227, 118, 77, 247, 146, 86},
			},
		},
		{
			"well-formed temporary credentials request",
			url.Values{
				"oauth_consumer_key":     []string{"dpf43f3p2l4k3l03"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131200"},
				"oauth_nonce":            []string{"wIjqoS"},
				"oauth_callback":         []string{"http://printer.example.com/ready"},
				"oauth_signature":        []string{"74KNZJeDHnMBp0EMJ9ZHt/XKycU="},
			},
			[]string{callback},
			&protocolParameters{
				clientID:  "dpf43f3p2l4k3l03",
				timestamp: time.Unix(137131200, 0),
				nonce:     "wIjqoS",
				callback:  mustParseURL("http://printer.example.com/ready"),
				signature: []byte{239, 130, 141, 100, 151, 131, 30, 115, 1, 167, 65, 12, 39, 214, 71, 183, 245, 202, 201, 197},
			},
		},
		{
			"oob callback",
			url.Values{
				"oauth_consumer_key":     []string{"dpf43f3p2l4k3l03"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131200"},
				"oauth_nonce":            []string{"wIjqoS"},
				"oauth_callback":         []string{"oob"},
				"oauth_signature":        []string{"74KNZJeDHnMBp0EMJ9ZHt/XKycU="},
			},
			[]string{callback},
			&protocolParameters{
				clientID:  "dpf43f3p2l4k3l03",
				timestamp: time.Unix(137131200, 0),
				nonce:     "wIjqoS",
				signature: []byte{239, 130, 141, 100, 151, 131, 30, 115, 1, 167, 65, 12, 39, 214, 71, 183, 245, 202, 201, 197},
			},
		},
		{
			"missing nonce parameter",
			url.Values{
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
			nil,
			nil,
		},
		{
			"multiple values",
			url.Values{
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"foobar", "bazqux"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
			nil,
			nil,
		},
		{
			"bad version",
			url.Values{
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"foobar"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
				"oauth_version":          []string{"2.0"},
			},
			nil,
			nil,
		},
		{
			"bad timestamp format",
			url.Values{
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"foobar"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"2017-04-20T10:40:53.160309Z"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
			nil,
			nil,
		},
		{
			"timestamp too large",
			url.Values{
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"foobar"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"9223372036854775808"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
			nil,
			nil,
		},
		{
			"PLAINTEXT",
			url.Values{
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"foobar"},
				"oauth_signature_method": []string{"PLAINTEXT"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
			nil,
			nil,
		},
		{
			"RSA-SHA1",
			url.Values{
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"foobar"},
				"oauth_signature_method": []string{"RSA-SHA1"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
			nil,
			nil,
		},
		{
			"empty value",
			url.Values{
				"oauth_consumer_key":     []string{""},
				"oauth_nonce":            []string{"foobar"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
			nil,
			nil,
		},
		{
			"invalid callback url",
			url.Values{
				"oauth_consumer_key":     []string{"dpf43f3p2l4k3l03"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131200"},
				"oauth_nonce":            []string{"wIjqoS"},
				"oauth_callback":         []string{"/ready"},
				"oauth_signature":        []string{"74KNZJeDHnMBp0EMJ9ZHt/XKycU="},
			},
			[]string{callback},
			nil,
		},
		{
			"missing callback in temporary credentials request",
			url.Values{
				"oauth_consumer_key":     []string{"dpf43f3p2l4k3l03"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131200"},
				"oauth_nonce":            []string{"wIjqoS"},
				"oauth_signature":        []string{"74KNZJeDHnMBp0EMJ9ZHt/XKycU="},
			},
			[]string{callback},
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newProtocolParameters(tc.params, tc.required, nil)
			if tc.want == nil {
				if err == nil {
					t.Fatal("want error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("want %#v; got %#v", tc.want, got)
				}
			}
		})
	}
}

func Test_baseString(t *testing.T) {
	testCases := []struct {
		name    string
		request string
		https   bool
		want    string
	}{
		{
			"rfc example",

			"POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				`Authorization: OAuth realm="Example",` +
				` oauth_consumer_key="9djdj82h48djs9d2",` +
				` oauth_token="kkk9d7dh3k39sjv7",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131201",` +
				` oauth_nonce="7d8f3e4a",` +
				` oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"` +
				"\r\n\r\n" +
				"c2&a3=2+q",
			false,
			"POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q" +
				"%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_" +
				"key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m" +
				"ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk" +
				"9d7dh3k39sjv7",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := readRequest(tc.request, tc.https)
			if err != nil {
				t.Fatal(err)
			}
			params, err := requestParameters(req)
			if err != nil {
				t.Fatal(err)
			}
			got := baseString(&request{Request: req, rawProto: params})
			if !bytes.Equal(got, []byte(tc.want)) {
				t.Errorf("got %#v; want %#v", string(got), string(tc.want))
			}
		})
	}
}

func Test_baseStringURI(t *testing.T) {
	testCases := []struct {
		name    string
		request string
		https   bool
		want    string
	}{
		{
			"rfc example 1",

			"GET /r%20v/X?id=123 HTTP/1.1\r\n" +
				"Host: EXAMPLE.COM:80\r\n\r\n",
			false,
			"http://example.com/r%20v/X",
		},
		{
			"rfc example 2",

			"GET /?q=1 HTTP/1.1\r\n" +
				"Host: www.example.net:8080\r\n\r\n",
			true,
			"https://www.example.net:8080/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := readRequest(tc.request, tc.https)
			if err != nil {
				t.Fatal(err)
			}
			got := baseStringURI(req)
			if got != tc.want {
				t.Errorf("got %#v; want %#v", got, tc.want)
			}
		})
	}
}

func Test_normalize(t *testing.T) {
	testCases := []struct {
		name   string
		params url.Values
		want   string
	}{
		{
			"rfc example",
			url.Values{
				"a2":                     []string{"r b"},
				"a3":                     []string{"2 q", "a"},
				"b5":                     []string{"=%3D"},
				"c@":                     []string{""},
				"c2":                     []string{""},
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"7d8f3e4a"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
			`a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7`,
		},
		{
			"tricky naming",
			url.Values{
				"foo":     []string{"1"},
				"foo-bar": []string{"2"},
			},
			`foo=1&foo-bar=2`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalize(tc.params)
			if got != tc.want {
				t.Errorf("want %#v; got %#v", tc.want, got)
			}
		})
	}
}

func Test_requestParameters(t *testing.T) {
	testCases := []struct {
		name    string
		request string
		want    map[string][]string
	}{
		{
			"rfc example",
			"POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				`Authorization: OAuth realm="Example",` +
				` oauth_consumer_key="9djdj82h48djs9d2",` +
				` oauth_token="kkk9d7dh3k39sjv7",` +
				` oauth_signature_method="HMAC-SHA1",` +
				` oauth_timestamp="137131201",` +
				` oauth_nonce="7d8f3e4a",` +
				` oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"` +
				"\r\n\r\n" +
				`c2&a3=2+q`,
			map[string][]string{
				"a2":                     []string{"r b"},
				"a3":                     []string{"2 q", "a"},
				"b5":                     []string{"=%3D"},
				"c@":                     []string{""},
				"c2":                     []string{""},
				"oauth_consumer_key":     []string{"9djdj82h48djs9d2"},
				"oauth_nonce":            []string{"7d8f3e4a"},
				"oauth_signature_method": []string{"HMAC-SHA1"},
				"oauth_timestamp":        []string{"137131201"},
				"oauth_token":            []string{"kkk9d7dh3k39sjv7"},
				"oauth_signature":        []string{"djosJKDKJSD8743243/jdk33klY="},
			},
		},
		{
			"no auth header",
			"POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
				`c2&a3=2+q`,
			map[string][]string{
				"a2": []string{"r b"},
				"a3": []string{"2 q", "a"},
				"b5": []string{"=%3D"},
				"c@": []string{""},
				"c2": []string{""},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := readRequest(tc.request, false)
			if err != nil {
				t.Fatal(err)
			}
			got, err := requestParameters(req)
			if err != nil {
				if tc.want != nil {
					t.Fatal(err)
				}
			} else {
				if tc.want == nil {
					t.Fatalf("want error; got %v", got)
				}
			}
			for k, want := range tc.want {
				if got, ok := got[k]; !ok {
					t.Errorf("want %s %#v but it's missing", k, want)
				} else if !reflect.DeepEqual(got, want) {
					t.Errorf("want %s %#v; got %#v", k, want, got)
				}
			}
			for k, got := range got {
				if _, ok := tc.want[k]; !ok {
					t.Errorf("got unwanted %s %#v", k, got)
				}
			}
		})
	}
}

func Test_authorizationHeaderParameters(t *testing.T) {
	testCases := []struct {
		name      string
		header    string
		want      map[string]string
		wantError bool
	}{
		{
			"rfc example",
			`OAuth realm="Example", oauth_consumer_key="jd83jd92dhsh93js", oauth_token="hdk48Djdsa", oauth_signature_method="PLAINTEXT", oauth_verifier="473f82d3", oauth_signature="ja893SD9%26xyz4992k83j47x0b"`,
			map[string]string{
				"oauth_consumer_key":     "jd83jd92dhsh93js",
				"oauth_token":            "hdk48Djdsa",
				"oauth_signature_method": "PLAINTEXT",
				"oauth_verifier":         "473f82d3",
				"oauth_signature":        "ja893SD9&xyz4992k83j47x0b",
			},
			false,
		},
		{
			"include all fields but realm",
			`OAuth foo="bar",oauth_version="1.0"`,
			map[string]string{
				"foo":           "bar",
				"oauth_version": "1.0",
			},
			false,
		},
		{
			"case insensitive auth scheme identifier",
			`oaUTH foo="bar"`,
			map[string]string{
				"foo": "bar",
			},
			false,
		},
		{
			"wrong auth type",
			`Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==`,
			nil,
			false,
		},
		{
			"missing quotation marks",
			`OAuth realm="Example", oauth_version=1.0`,
			nil,
			true,
		},
		{
			"missing equal sign",
			`OAuth realm="Example", oauth_version, oauth_signature=""`,
			nil,
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authorizationHeaderParameters(tc.header)
			if tc.wantError {
				if err == nil {
					t.Fatalf("want error; got %v", got)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Log(got)
			for k, want := range tc.want {
				if got, ok := got[k]; !ok {
					t.Errorf("want %s %#v but it's missing", k, want)
				} else if len(got) != 1 {
					t.Errorf("want %s %#v; got %#v", k, want, got)
				} else if got := got[0]; got != want {
					t.Errorf("want %s %#v; got %#v", k, want, got)
				}
			}
			for k, got := range got {
				if _, ok := tc.want[k]; !ok {
					t.Errorf("got unwanted %s %#v", k, got)
				}
			}
		})
	}
}

func readRequest(s string, https bool) (*http.Request, error) {
	r := bufio.NewReader(strings.NewReader(s))
	req, err := http.ReadRequest(r)
	if err != nil {
		return req, err
	}
	if https {
		req.TLS = new(tls.ConnectionState)
	}
	req.Body = ioutil.NopCloser(r)
	return req, nil
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func newTestServer() *Server {
	var server *Server

	db := newSqliteDB()
	server = &Server{
		Store:               db,
		Realm:               "Photos",
		MaxAge:              5 * time.Minute,
		MaxSkew:             5 * time.Minute,
		skipVerifySignature: true,
		skipVerifyNonce:     true,
		clock:               new(clock),
	}
	*(server.clock) = clock(time.Unix(137131500, 0))
	db.mustAddClient(printerClient)
	db.mustAddToken(tempToken)
	db.mustAddToken(photoToken)
	db.mustAddToken(unrelatedToken)
	db.mustAddToken(unrelatedTempToken)

	return server
}

func errCode(err error) int {
	err = errors.Cause(err)
	if err == nil {
		return http.StatusOK
	}
	switch err.(type) {
	case unauthorized:
		return http.StatusUnauthorized
	case badRequestError:
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}
