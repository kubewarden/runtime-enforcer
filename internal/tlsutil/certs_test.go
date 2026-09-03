package tlsutil_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/internal/tlsutil"
)

func generateTestKeyPair(t *testing.T, dir string) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(dir, tlsutil.CertFile)
	keyPath := filepath.Join(dir, tlsutil.KeyFile)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeFile(t, certPath, certPEM)

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	writeFile(t, keyPath, keyPEM)

	return certPath, keyPath
}

func generateCACertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCACertPool(t *testing.T) {
	t.Run("valid PEM", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		writeFile(t, path, generateCACertPEM(t))

		pool, err := tlsutil.LoadCACertPool(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool == nil {
			t.Fatal("expected non-nil cert pool")
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := tlsutil.LoadCACertPool(filepath.Join(t.TempDir(), "nonexistent.crt"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.crt")
		writeFile(t, path, []byte("not a certificate"))

		_, err := tlsutil.LoadCACertPool(path)
		if err == nil {
			t.Fatal("expected error for invalid PEM")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.crt")
		writeFile(t, path, []byte{})

		_, err := tlsutil.LoadCACertPool(path)
		if err == nil {
			t.Fatal("expected error for empty file")
		}
	})
}

func TestLoadKeyPair(t *testing.T) {
	t.Run("valid key pair", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestKeyPair(t, dir)

		cert, err := tlsutil.LoadKeyPair(certPath, keyPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cert.Certificate) == 0 {
			t.Fatal("expected at least one certificate in the chain")
		}
	})

	t.Run("missing cert file", func(t *testing.T) {
		dir := t.TempDir()
		_, keyPath := generateTestKeyPair(t, dir)
		os.Remove(filepath.Join(dir, tlsutil.CertFile))

		_, err := tlsutil.LoadKeyPair(filepath.Join(dir, tlsutil.CertFile), keyPath)
		if err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})

	t.Run("missing key file", func(t *testing.T) {
		dir := t.TempDir()
		certPath, _ := generateTestKeyPair(t, dir)
		os.Remove(filepath.Join(dir, tlsutil.KeyFile))

		_, err := tlsutil.LoadKeyPair(certPath, filepath.Join(dir, tlsutil.KeyFile))
		if err == nil {
			t.Fatal("expected error for missing key file")
		}
	})
}

func TestValidateCertDir(t *testing.T) {
	t.Run("valid directory", func(t *testing.T) {
		dir := t.TempDir()
		generateTestKeyPair(t, dir)

		if err := tlsutil.ValidateCertDir(dir); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty path", func(t *testing.T) {
		if err := tlsutil.ValidateCertDir(""); err == nil {
			t.Fatal("expected error for empty path")
		}
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		if err := tlsutil.ValidateCertDir("/nonexistent/path"); err == nil {
			t.Fatal("expected error for nonexistent directory")
		}
	})

	t.Run("directory without key pair", func(t *testing.T) {
		dir := t.TempDir()
		if err := tlsutil.ValidateCertDir(dir); err == nil {
			t.Fatal("expected error for directory without key pair")
		}
	})
}
