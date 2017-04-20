package oauth1

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mrjones_oauth "github.com/mrjones/oauth"
)

const (
	clientID     = "foo"
	clientSecret = "bar"
)

func TestFlow(t *testing.T) {
	mux, s := newHTTPTestServer(t)
	defer s.Close()
	c := mrjones_oauth.NewConsumer(clientID, clientSecret, mrjones_oauth.ServiceProvider{
		RequestTokenUrl:   s.URL + "/initiate",
		AuthorizeTokenUrl: s.URL + "/authorize",
		AccessTokenUrl:    s.URL + "/token",
	})

	// initiate request
	rtoken, login, err := c.GetRequestTokenAndUrl(s.URL + "/callback")
	if err != nil {
		t.Fatal("failed to acquire temporary credentials:", err)
	}
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if v := r.Form.Get("oauth_token"); v != rtoken.Token {
			t.Fatalf("token mismatch! want %s; got %s", rtoken.Token, v)
		}
		w.Write([]byte(r.Form.Get("oauth_verifier")))
	})

	// log in and authorize request
	res, err := http.Get(login)
	if err != nil {
		t.Fatal("failed to authorize:", err)
	}
	defer res.Body.Close()
	var verifier string
	{
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal("failed to read response:", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("failed to authorize: %s", body)
		}
		verifier = string(body)
	}

	atoken, err := c.AuthorizeToken(rtoken, verifier)
	if err != nil {
		t.Fatal("failed to verify:", err)
	}
	client, err := c.MakeHttpClient(atoken)
	if err != nil {
		t.Fatal(err)
	}
	res, err = client.Get(s.URL + "/protected")
	if err != nil {
		t.Fatal("failed to access protected resource:", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		t.Fatalf("failed to access protected resource: %s", body)
	}
}

func newHTTPTestServer(t *testing.T) (*http.ServeMux, *httptest.Server) {
	db := newSqliteDB()
	s := &Server{
		Store:   db,
		MaxAge:  5 * time.Second,
		MaxSkew: time.Second,

		LogClientError: testLogger(t),
		LogServerError: testLogger(t),
	}
	clientCredentials := &ClientCredentials{
		ID:     clientID,
		Secret: clientSecret,
	}
	db.mustAddClient(clientCredentials)

	mux := http.NewServeMux()
	mux.HandleFunc("/initiate", s.TempCredentials)
	mux.Handle("/authorize", s.Authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cli := GetClient(r.Context())
		tkn := GetToken(r.Context())
		t.Log("client:", cli)
		t.Log("token:", tkn)
		http.Redirect(w, r, tkn.VerifiedCallback().String(), http.StatusFound)
	})))
	mux.HandleFunc("/token", s.TokenCredentials)
	mux.Handle("/protected", s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cli := GetClient(r.Context())
		tkn := GetToken(r.Context())
		if cli == nil || tkn == nil {
			t.Log("client:", cli)
			t.Log("token:", tkn)
			http.Error(w, "missing token/client", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("ok!"))
	})))
	return mux, httptest.NewServer(mux)
}
