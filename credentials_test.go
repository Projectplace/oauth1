package oauth1

import (
	"fmt"
	"net/url"
	"reflect"
	"testing"
)

func TestCallback(t *testing.T) {
	testCases := []struct {
		name     string
		callback *url.URL
		want     string
	}{
		{
			"no previous query",
			mustParseURL("http://foo.example.com"),
			"http://foo.example.com?oauth_token=foo&oauth_verifier=slash%2Fslash",
		},
		{
			"append to query",
			mustParseURL("http://foo.example.com?xxx=888"),
			"http://foo.example.com?xxx=888&oauth_token=foo&oauth_verifier=slash%2Fslash",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tkn := &TempCredentials{
				ID:               "foo",
				Secret:           "bar",
				ClientID:         "baz",
				Callback:         tc.callback,
				VerificationCode: "slash/slash",
			}
			url := tkn.verifiedCallback()
			if url != tc.want {
				t.Errorf("want %s, got %s", tc.want, url)
			}
		})
	}
}

func (c *ClientCredentials) String() string {
	return fmt.Sprintf("<client %v>", c.ID)
}

func (c *ClientCredentials) is(cc *ClientCredentials) bool {
	return reflect.DeepEqual(c, cc)
}

func (t *TokenCredentials) String() string {
	return fmt.Sprintf("<token %v>", t.ID)
}

func (t *TokenCredentials) is(tt *TokenCredentials) bool {
	return reflect.DeepEqual(t, tt)
}

func (t *TempCredentials) String() string {
	return fmt.Sprintf("<temp %v>", t.ID)
}

func (t *TempCredentials) is(tt *TempCredentials) bool {
	return reflect.DeepEqual(t, tt)
}
