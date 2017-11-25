package main

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/Projectplace/oauth1"
	sqlite3 "github.com/mattn/go-sqlite3"
)

var oauth *oauth1.Server

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal("could not open database", err)
	}
	_, err = db.Exec(`
		create table clients (
			id      char(32) primary key,
			secret  char(40) not null,
			name    text not null
		);

		create table tokens (
			id         char(32) primary key,
			secret     char(40) not null,
			client_id  char(32) not null references clients(id) on delete cascade,
			username   text not null
		);

		create table tempcreds (
			id         char(32) primary key,
			secret     char(40) not null,
			client_id  char(32) not null references clients(id) on delete cascade,
			callback   text,
			code       char(40) not null,
			username   text default null
		);

		create table nonces (
			nonce     varchar(128) not null,
			timestamp timestamp,
			client_id char(32) references clients(id) on delete cascade,
			token_id  char(32) references tokens(id) on delete cascade
		);

		create unique index nonce_idx on nonces (
			nonce,
			timestamp,
			client_id,
			token_id
		);

		insert into clients
			(id, secret, name)
		values
			('c0d0d372c68d12534be1bc8388ae05c7', '63563fb9c867a7edcf47fa9a77933148875368a3', 'Exemplifier');
		`,
	)
	if err != nil {
		log.Fatal("could not initialize database", err)
	}

	oauth = &oauth1.Server{
		Store: &Store{db},
		Realm: "example",
	}

	http.HandleFunc("/oauth/initiate", initiate)
	http.HandleFunc("/oauth/authorize", authorize)
	http.HandleFunc("/oauth/token", token)
	http.HandleFunc("/protected", greet)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initiate(w http.ResponseWriter, r *http.Request) {
	t, err := oauth.InitiateAuthorization(r)
	if err != nil {
		log.Println("could not create temporary credentials:", err)
		oauth1.WriteError(w, err)
		return
	}
	log.Printf("created temporary credentials %v for client %v", t.ID, t.ClientID)
	t.WriteTo(w)
}

func authorize(w http.ResponseWriter, r *http.Request) {
	c, t, err := oauth.RequestAuthorization(r)
	if err != nil {
		log.Println("authorization request failed:", err)
		oauth1.WriteError(w, err)
		return
	}

	// Proper login as well as CSRF protection have been omitted in this
	// example for the sake of brevity. All users have the password "hunter2".
	username, password, _ := r.BasicAuth()
	if password != "hunter2" {
		w.Header().Set("WWW-Authenticate", `Basic realm="example"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tpl := template.Must(template.New("authorizeRequest").Parse(`
		<!DOCTYPE html>
		<title>authorize access</title>
		<body>
			Grant {{ .ClientName }} access?
			<form method="POST">
				<input type="hidden" name="oauth_token" value="{{ .TokenID }}">
				<input type="submit" value="ok">
			</form>
		</body>
		`))
		data := struct {
			ClientName string
			TokenID    string
		}{
			TokenID:    t.ID,
			ClientName: c.Custom.(string),
		}
		tpl.Execute(w, data)
	case "POST":
		err := oauth.Store.(*Store).claimToken(r.Context(), t, username)
		if err != nil {
			log.Println("failed to grant authorization:", err)
			oauth1.WriteError(w, err)
			return
		}
		log.Println("authorization granted by", username)
		if t.Callback != nil {
			t.Redirect(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Verification code: %v", t.VerificationCode)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func token(w http.ResponseWriter, r *http.Request) {
	t, err := oauth.ConcludeAuthorization(r)
	if err != nil {
		log.Println("could not create token credentials", err)
		oauth1.WriteError(w, err)
		return
	}
	log.Println("generated token credentials")
	t.WriteTo(w)
}

func greet(w http.ResponseWriter, r *http.Request) {
	c, t, err := oauth.Authenticate(r)
	if err != nil {
		log.Println("failed to authenticate request to protected resource:", err)
		oauth1.WriteError(w, err)
		return
	}
	log.Println("successfully authenticated request to protected resource")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%v successfully made a call", c.Custom)
	if t != nil {
		fmt.Fprintf(w, " on behalf of %v.", t.Custom)
	}
}

type Store struct {
	db *sql.DB
}

func (s *Store) GetClient(ctx context.Context, id string) (*oauth1.ClientCredentials, error) {
	var name string
	c := oauth1.ClientCredentials{ID: id}
	err := s.db.QueryRowContext(ctx, `select secret, name from clients where id = ?`, id).Scan(
		&c.Secret, &name,
	)
	switch {
	case err == sql.ErrNoRows:
		return nil, oauth1.ErrNotFound
	case err != nil:
		return nil, err
	}
	c.Custom = name

	return &c, nil
}

func (s *Store) GetToken(ctx context.Context, id string) (*oauth1.TokenCredentials, error) {
	var username string

	t := oauth1.TokenCredentials{ID: id}
	err := s.db.QueryRowContext(ctx, `
		select
			secret, client_id, username
		from tokens
		where id = ?`,
		id,
	).Scan(&t.Secret, &t.ClientID, &username)
	t.Custom = username
	switch {
	case err == sql.ErrNoRows:
		return nil, oauth1.ErrNotFound
	case err != nil:
		return nil, err
	}

	return &t, err
}

func (s *Store) GetTemp(ctx context.Context, id string) (*oauth1.TempCredentials, error) {
	var (
		callback *string
		username *string
	)

	t := oauth1.TempCredentials{ID: id}
	err := s.db.QueryRowContext(ctx, `
		select
			secret, client_id, callback, code, username
		from tempcreds
		where id = ?`,
		id,
	).Scan(&t.Secret, &t.ClientID, &callback, &t.VerificationCode, &username)
	switch {
	case err == sql.ErrNoRows:
		return nil, oauth1.ErrNotFound
	case err != nil:
		return nil, err
	}

	if callback != nil {
		t.Callback, err = url.Parse(*callback)
	}
	if username != nil {
		t.Custom = *username
	}

	return &t, err
}

func (s *Store) AddTempCredentials(ctx context.Context, t *oauth1.TempCredentials) error {
	var callback *string

	if t.Callback != nil {
		callback = new(string)
		*callback = t.Callback.String()
	}

	_, err := s.db.ExecContext(ctx, `
		insert into tempcreds
			(id, secret, client_id, callback, code)
		values
			(?, ?, ?, ?, ?)`,
		t.ID, t.Secret, t.ClientID, callback, t.VerificationCode,
	)

	return err
}

func (s *Store) ConvertTempCredentials(ctx context.Context, old *oauth1.TempCredentials, new *oauth1.TokenCredentials) error {
	_, err := s.db.ExecContext(ctx, `delete from tempcreds where id = ?`, old.ID)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		insert into tokens
			(id, secret, client_id, username)
		values
			(?, ?, ?, ?)`,
		new.ID, new.Secret, new.ClientID, new.Custom,
	)
	return err
}

func (s *Store) ConsumeNonce(ctx context.Context, nonce string, timestamp time.Time, clientID, tokenID string) error {
	const maxNonceSize = 128
	if len(nonce) > maxNonceSize {
		nonce = nonce[:maxNonceSize]
	}

	_, err := s.db.ExecContext(ctx, `
		insert into nonces
			(nonce, timestamp, client_id, token_id)
		values
			(?, ?, ?, ?)`,
		nonce, timestamp, clientID, tokenID,
	)
	if err, ok := err.(sqlite3.Error); ok && err.ExtendedCode == sqlite3.ErrConstraintUnique {
		return oauth1.ErrNonceAlreadyUsed
	}
	return err
}

func (s *Store) claimToken(ctx context.Context, t *oauth1.TempCredentials, username string) error {
	_, err := s.db.ExecContext(ctx, `update tempcreds set username = ? where id = ?`, username, t.ID)
	return err
}
