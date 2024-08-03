package middleware

import (
	"net/http"
)

type X509Middleware struct {
	handler                  http.Handler
	unauthorizedResponseCode int
	unauthorizedResponseBody []byte
}

func (x *X509Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(x.unauthorizedResponseCode)
		w.Write(x.unauthorizedResponseBody)
		return
	}

	x.handler.ServeHTTP(w, r)
}

func NewX509Middleware(handler http.Handler) *X509Middleware {
	return &X509Middleware{
		handler:                  handler,
		unauthorizedResponseCode: http.StatusUnauthorized,
		unauthorizedResponseBody: []byte("unauthorized"),
	}
}
