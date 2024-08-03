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
			ClientAuth: tls.RequestClientCert,
		},
	}

	server.ListenAndServeTLS("path/to/tls.crt", "path/to/tls.key")
}
