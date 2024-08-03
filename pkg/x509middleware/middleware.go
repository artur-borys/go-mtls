// Package middleware provides middlewares for mTLS
package x509middleware

import (
	"net/http"
)

// X509Middleware is the middleware to be used with optional mTLS
type X509Middleware struct {
	handler                  http.Handler
	unauthorizedResponseCode int
	unauthorizedResponseBody []byte
}

// ServeHTTP is the handler of HTTP requests which continues with processing
// when the request contains a valid client certificate.
// Otherwise it returns the configured response body and HTTP status
//
// (HTTP 401 unauthorized by default)
func (x *X509Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(x.unauthorizedResponseCode)
		w.Write(x.unauthorizedResponseBody)
		return
	}

	x.handler.ServeHTTP(w, r)
}

// New returns a default instance of the [X509Middleware] middleware
func New(handler http.Handler) *X509Middleware {
	return &X509Middleware{
		handler:                  handler,
		unauthorizedResponseCode: http.StatusUnauthorized,
		unauthorizedResponseBody: []byte("unauthorized"),
	}
}
