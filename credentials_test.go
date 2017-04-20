package oauth1

import (
	"net/url"
	"testing"
)

func TestTokenCallback(t *testing.T) {
	testCases := []struct {
		name     string
		callback *url.URL
		want     *url.URL
	}{
		{
			"no previous query",
			mustParseURL("http://foo.example.com"),
			mustParseURL("http://foo.example.com?oauth_token=foo&oauth_verifier=slash%2Fslash"),
		},
		{
			"append to query",
			mustParseURL("http://foo.example.com?xxx=888"),
			mustParseURL("http://foo.example.com?xxx=888&oauth_token=foo&oauth_verifier=slash%2Fslash"),
		},
		{
			"no callback",
			nil,
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tkn := &TokenCredentials{
				ID:               "foo",
				Secret:           "bar",
				ClientID:         "baz",
				Callback:         tc.callback,
				VerificationCode: "slash/slash",
			}
			u := tkn.VerifiedCallback()
			if u == tc.want {
				return
			}
			if u == nil || tc.want == nil || tc.want.String() != u.String() {
				t.Fatalf("want %s, got %s", tc.want, u)
			}
		})
	}
}
