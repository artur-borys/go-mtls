# go-mtls

This library provides a basic middleware to be used with optional mTLS.
With this middleware, you can require a valid client certificate only for
specific endpoint(s).

This is especially useful if your app/microservice doesn't require a fullblown auth system
and you want to keep things simple.

With this library, you can secure the endpoints which matter, while keeping those
less vulnerable easily accessible (like `/liveness`, `/readiness` and `/metrics` endpoint etc.)

# Installation

```bash
go get github.com/artur-borys/go-mtls@v0.0.1
```

# Usage

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"

	"github.com/artur-borys/go-mtls/pkg/x509middleware"
)

func main() {
	mux := http.NewServeMux()

	// Add x509middleware to secured endpoint
	mux.Handle("/api/v1/secured", x509middleware.New(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		}),
	))

	// Don't add the middleware to the endpoints you want to be accessible without a client cert
	mux.Handle("/api/v1/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("unprotected endpoint"))
	}))

	// Load trusted CA(s) to the pool
	caCert, err := os.ReadFile("path/to/ca.crt")
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
		os.Exit(1)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	server := http.Server{
		Addr: ":8080",
		TLSConfig: &tls.Config{
			ClientCAs:  caCertPool,
			// IMPORTANT
			// This will make the client certificate optional, but when provided - make sure it's trusted
			ClientAuth: tls.RequestClientCert,
		},
	}

	server.ListenAndServeTLS("path/to/tls.crt", "path/to/tls.key")
}

```
