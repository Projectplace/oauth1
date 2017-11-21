package oauth1

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

var (
	// ErrNotFound is the error returned by Store methods if a token or client
	// can not be found.
	ErrNotFound = errors.New("not found")
	// ErrNonceAlreadyUsed is the error returned by ConsumeNonce if a nonce is
	// re-used.
	ErrNonceAlreadyUsed = errors.New("nonce already used")
)

// WriteError encodes and writes err to w with the appropriate status code.
func WriteError(w http.ResponseWriter, err error) {
	switch e := errors.Cause(err).(type) {
	case badRequestError:
		http.Error(w, fmt.Sprintf("%s: %s", http.StatusText(http.StatusBadRequest), e.msg), http.StatusBadRequest)
	case unauthorized:
		if e.realm != "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`OAuth realm="%s"`, e.realm))
		}
		http.Error(w, fmt.Sprintf("%s: %s", http.StatusText(http.StatusUnauthorized), e), http.StatusUnauthorized)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// IsInternal returns true if err is caused by an internal server error.
func IsInternal(err error) bool {
	switch errors.Cause(err).(type) {
	case badRequestError, unauthorized:
		return false
	}
	return true
}

type badRequestError struct {
	err error
	msg string
}

func (e badRequestError) Error() string {
	return e.err.Error()
}

type unauthorized struct {
	msg   string
	realm string
}

func (e unauthorized) Error() string {
	return e.msg
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
