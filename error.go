package oauth1

import (
	"fmt"

	"github.com/pkg/errors"
)

var (
	// ErrNotFound is the error resulting if a matching token or client can not be found.
	ErrNotFound = errors.New("not found")
	// ErrNonceAlreadyUsed is the error resulting if a nonce is re-used.
	ErrNonceAlreadyUsed = unauthorized("nonce already used")
)

type badRequestError struct {
	err error
	msg string
}

func (e badRequestError) Error() string {
	return e.err.Error()
}

type unauthorized string

func (e unauthorized) Error() string {
	return string(e)
}

func newBadRequest(msg string, err error) badRequestError {
	return badRequestError{errors.Wrap(err, msg), msg}
}

func badValue(k string, err error) badRequestError {
	msg := fmt.Sprintf("bad value for %v parameter", k)
	return newBadRequest(msg, err)
}

func missingParameter(k string) badRequestError {
	msg := fmt.Sprintf("missing %v parameter", k)
	return badRequestError{err: errors.New(msg), msg: msg}
}
