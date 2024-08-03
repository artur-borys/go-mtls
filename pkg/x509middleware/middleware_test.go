package x509middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var port = 8080

// TestNonTls
// Make sure that the middleware is basically a noop, when server is not using TLS
func TestNonTLS(t *testing.T) {
	mux := http.NewServeMux()

	mux.Handle("/", New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})))

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go server.ListenAndServe()

	defer server.Close()

	client := http.Client{}

	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/", port))

	assert.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	assert.NoError(t, err)

	assert.Equal(t, "ok", string(body))
}

// TestTls
// The server has ClientAuth: RequestClientCert
// It means that the cert is not required, but if provided - will be verified upon handshake
// Endpoint / - it's protected by the middleware. It's requiring a client certificate
// Endpoint /no-auth - it's not protected. There's no middleware, so requests without certificate won't be rejected
//
// Scenario 1
// The client sends a request to / without a cert - the server should respond with HTTP 401
// The client sends a request to /no-auth without a cert - the server should respond HTTP 200
//
// Scenario 2
// The client sends a request to / with a valid cert - the server should respond with HTTP 200
func TestTls(t *testing.T) {
	// Generate CA keypair
	caKeyBytes, caCertBytes, err := GenerateRootKeyPair()
	assert.NoError(t, err)

	// Translate the keypair back to whole x509.certificate
	caCert, err := x509.ParseCertificate(caCertBytes)
	assert.NoError(t, err)

	// Create a trust pool with the CA cert
	trustPool := x509.NewCertPool()
	trustPool.AddCert(caCert)

	// Parse the EC private key from the bytes to be used
	caKey, err := x509.ParseECPrivateKey(caKeyBytes)
	assert.NoError(t, err)

	// Generate the server TLS keypair
	serverSubject := pkix.Name{
		CommonName:   "server",
		Organization: []string{"artur-borys"},
	}
	serverKey, serverCert, err := GenerateLeafKeyPair(serverSubject, []string{"localhost"}, caCert, caKey)
	assert.NoError(t, err)

	serverTlsCert, err := CertFromDer(serverKey, serverCert)
	assert.NoError(t, err)

	// Generate the client TLS keypair
	clientSubject := pkix.Name{
		CommonName:   "client",
		Organization: []string{"artur-borys"},
	}
	clientKey, clientCert, err := GenerateLeafKeyPair(clientSubject, []string{}, caCert, caKey)
	assert.NoError(t, err)

	clientTlsCert, err := CertFromDer(clientKey, clientCert)
	assert.NoError(t, err)

	// Setup the server
	mux := http.NewServeMux()
	mux.Handle("/", New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})))
	mux.Handle("/no-auth", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientAuth:   tls.RequestClientCert,
			Certificates: []tls.Certificate{serverTlsCert},
			ClientCAs:    trustPool,
		},
	}

	go server.ListenAndServeTLS("", "")

	// Setup the client without client certs
	clientNoCerts := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: trustPool,
			},
		},
	}

	// Setup the client with client certs
	clientCerts := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      trustPool,
				Certificates: []tls.Certificate{clientTlsCert},
			},
		},
	}

	// Scenario 1
	respNoCerts, err := clientNoCerts.Get(fmt.Sprintf("https://localhost:%d/", port))
	assert.NoError(t, err)
	defer respNoCerts.Body.Close()

	bodyNoCerts, err := io.ReadAll(respNoCerts.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, respNoCerts.StatusCode)
	assert.Equal(t, "unauthorized", string(bodyNoCerts))

	respNoCertsNoAuth, err := clientNoCerts.Get(fmt.Sprintf("https://localhost:%d/no-auth", port))
	assert.NoError(t, err)
	defer respNoCertsNoAuth.Body.Close()

	bodyNoCertsNoAuth, err := io.ReadAll(respNoCertsNoAuth.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, respNoCertsNoAuth.StatusCode)
	assert.Equal(t, "ok", string(bodyNoCertsNoAuth))

	// Scenario 2
	respCerts, err := clientCerts.Get(fmt.Sprintf("https://localhost:%d/", port))
	assert.NoError(t, err)

	defer respNoCerts.Body.Close()

	bodyCerts, err := io.ReadAll(respCerts.Body)

	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, respCerts.StatusCode)
	assert.Equal(t, "ok", string(bodyCerts))
}

func LeafCertTemplate(subject pkix.Name, dnsNames []string, notBefore time.Time, notAfter time.Time) (x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		return x509.Certificate{}, err
	}

	return x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}, nil
}

func RootCertTemplate(subject pkix.Name, notBefore time.Time, notAfter time.Time) (x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		return x509.Certificate{}, err
	}

	return x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}, nil
}

func GenerateRootKeyPair() (privateKeyBytes, certDerBytes []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		return nil, nil, err
	}

	subject := pkix.Name{
		CommonName:   "root CA",
		Organization: []string{"artur-borys"},
	}

	certTemplate, err := RootCertTemplate(subject, time.Now(), time.Now().Add(time.Hour))

	if err != nil {
		return
	}

	certDerBytes, err = x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)

	if err != nil {
		return
	}

	privateKeyBytes, err = x509.MarshalECPrivateKey(privateKey)

	return
}

func GenerateLeafKeyPair(subject pkix.Name, dnsNames []string, issuerCert *x509.Certificate, issuerPrivateKey *ecdsa.PrivateKey) (privateKeyBytes, certDerBytes []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		return nil, nil, err
	}

	certTemplate, err := LeafCertTemplate(subject, dnsNames, time.Now(), time.Now().Add(time.Minute*10))

	if err != nil {
		return nil, nil, err
	}

	certDerBytes, err = x509.CreateCertificate(rand.Reader, &certTemplate, issuerCert, &privateKey.PublicKey, issuerPrivateKey)

	if err != nil {
		return
	}

	privateKeyBytes, err = x509.MarshalECPrivateKey(privateKey)

	return
}

func CertFromDer(keyDer []byte, certDer []byte) (tls.Certificate, error) {
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})

	return tls.X509KeyPair(certPem, keyPem)
}
