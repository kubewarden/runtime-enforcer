package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// CertFile is the standard file name for a TLS certificate.
	CertFile = "tls.crt"
	// KeyFile is the standard file name for a TLS private key.
	KeyFile = "tls.key"
	// CAFile is the standard file name for a CA certificate.
	CAFile = "ca.crt"
)

// LoadCACertPool reads PEM-encoded CA certificates from the given path and
// return an "[x509.CertPool]" containing it.
// This is useful for setting up TLS connections that verify against a custom CA,
// and supports certificate rotation when called on each handshake.
func LoadCACertPool(path string) (*x509.CertPool, error) {
	caPem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPem) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", path)
	}
	return pool, nil
}

// LoadKeyPair loads a TLS certificate and private key from the given paths.
// It is a thin wrapper around "[tls.LoadX509KeyPair]" that normalises the error
// message for consistency.
func LoadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load key pair (%s, %s): %w", certPath, keyPath, err)
	}
	return cert, nil
}

// ValidateCertDir checks that dirPath exists and contains a loadable TLS key
// pair (tls.crt + tls.key). It is intended for fail-fast validation at
// startup before any connections are attempted.
func ValidateCertDir(dirPath string) error {
	if dirPath == "" {
		return errors.New("certificate directory path is empty")
	}
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate directory does not exist: %w", err)
	}
	_, err := LoadKeyPair(
		filepath.Join(dirPath, CertFile),
		filepath.Join(dirPath, KeyFile),
	)
	return err
}
