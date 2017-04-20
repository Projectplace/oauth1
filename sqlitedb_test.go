package oauth1

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"time"

	"github.com/mattn/go-sqlite3"
)

func newSqliteDB() *sqliteDB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec(`
	create table clients (
		id     text primary key,
		secret text not null
	);
	create table tokens (
		id           text primary key,
		secret       text not null,
		client_id    text references clients (id),
		callback_url text null default null,
		verifier     text null default null
	);
	create table nonces (
		nonce text,
		timestamp datetime,
		client_id text references clients (id),
		token_id text references tokens (id)
	);
	create unique index nonce_idx on nonces (
		nonce,
		timestamp,
		client_id,
		token_id
	)`)
	if err != nil {
		panic(err)
	}

	return (*sqliteDB)(db)
}

type sqliteDB sql.DB

var _ Store = (*sqliteDB)(nil)

func (db *sqliteDB) GetClient(ctx context.Context, id string) (*ClientCredentials, error) {
	c := &ClientCredentials{ID: id}

	err := (*sql.DB)(db).QueryRowContext(ctx, `select secret from clients where id = ?`, id).Scan(&c.Secret)

	if err != nil {
		c = nil
	}
	if err == sql.ErrNoRows {
		err = ErrNotFound
	}
	return c, err
}

func (db *sqliteDB) AddToken(ctx context.Context, t *TokenCredentials) error {
	var callback, verifier *string
	if t.IsTemporary() {
		verifier = &t.VerificationCode
		if t.Callback != nil {
			s := t.Callback.String()
			callback = &s
		}
	}
	_, err := (*sql.DB)(db).ExecContext(ctx, `
		insert into tokens
			(id, secret, client_id, callback_url, verifier)
		values
			(?, ?, ?, ?, ?)`,
		t.ID, t.Secret, t.ClientID, callback, verifier,
	)
	return err
}

func (db *sqliteDB) GetToken(ctx context.Context, id string) (*TokenCredentials, error) {
	var callback, verifier *string

	t := &TokenCredentials{ID: id}
	err := (*sql.DB)(db).QueryRowContext(ctx, `
	select secret, client_id, callback_url, verifier
		from tokens
		where id = ?`,
		id,
	).Scan(&t.Secret, &t.ClientID, &callback, &verifier)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if verifier != nil {
		t.VerificationCode = *verifier
	}
	if callback != nil {
		t.Callback, err = url.Parse(*callback)
	}
	return t, err
}

func (db *sqliteDB) ReplaceToken(ctx context.Context, old, new *TokenCredentials) error {
	if new.IsTemporary() {
		return errors.New("temporary credentials")
	}

	res, err := (*sql.DB)(db).ExecContext(ctx, `
		update tokens
		set
			id = ?,
			secret = ?,
			callback_url = null,
			verifier = null
		where id = ?`,
		new.ID, new.Secret, old.ID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		err = ErrNotFound
	}
	return err
}

func (db *sqliteDB) ConsumeNonce(ctx context.Context, nonce string, timestamp time.Time, clientID string, tokenID string) error {
	_, err := (*sql.DB)(db).ExecContext(ctx, `
	insert into nonces
		(nonce, timestamp, client_id, token_id)
	values
		(?, ?, ?, ?)`,
		nonce, timestamp, clientID, tokenID,
	)
	if err, ok := err.(sqlite3.Error); ok && err.ExtendedCode == sqlite3.ErrConstraintUnique {
		return ErrNonceAlreadyUsed
	}
	return err
}

type executor interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

func addToken(ctx context.Context, x executor, t *TokenCredentials) error {
	var callback, verifier *string
	if t.IsTemporary() {
		verifier = &t.VerificationCode
		if t.Callback != nil {
			s := t.Callback.String()
			callback = &s
		}
	}
	_, err := x.ExecContext(ctx,
		`insert into tokens (id, secret, client_id, callback_url, verifier) values (?, ?, ?, ?, ?)`,
		t.ID, t.Secret, t.ClientID, callback, verifier,
	)
	return err
}

func (db *sqliteDB) mustAddClient(c *ClientCredentials) {
	_, err := (*sql.DB)(db).Exec(`insert into clients (id, secret) values (?, ?)`, c.ID, c.Secret)
	if err != nil {
		panic(err)
	}
}

func (db *sqliteDB) mustAddToken(t *TokenCredentials) {
	err := addToken(context.Background(), (*sql.DB)(db), t)
	if err != nil {
		panic(err)
	}
}
