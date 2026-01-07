package ntlmcbt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// generateTestCert creates a self-signed test certificate for testing.
func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Parse it back to get a Certificate struct
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func TestGSSChannelBindings_Pack(t *testing.T) {
	// Test with empty addresses (typical for TLS bindings)
	cb := &GSSChannelBindings{
		InitiatorAddrType: 0,
		InitiatorAddress:  nil,
		AcceptorAddrType:  0,
		AcceptorAddress:   nil,
		ApplicationData:   []byte("tls-server-end-point:test"),
	}

	packed := cb.Pack()

	// Verify structure:
	// - InitiatorAddrType: 4 bytes (0)
	// - InitiatorLength: 4 bytes (0)
	// - AcceptorAddrType: 4 bytes (0)
	// - AcceptorLength: 4 bytes (0)
	// - ApplicationDataLength: 4 bytes
	// - ApplicationData: variable

	expectedPrefix := []byte{
		0, 0, 0, 0, // InitiatorAddrType
		0, 0, 0, 0, // InitiatorLength (empty)
		0, 0, 0, 0, // AcceptorAddrType
		0, 0, 0, 0, // AcceptorLength (empty)
	}

	if !bytes.HasPrefix(packed, expectedPrefix) {
		t.Errorf("packed prefix mismatch\ngot:  %s\nwant: %s",
			hex.EncodeToString(packed[:16]),
			hex.EncodeToString(expectedPrefix))
	}

	// Check application data length
	appDataLen := uint32(len("tls-server-end-point:test"))
	expectedAppDataLenBytes := []byte{byte(appDataLen), 0, 0, 0}
	if !bytes.Equal(packed[16:20], expectedAppDataLenBytes) {
		t.Errorf("application data length mismatch\ngot:  %s\nwant: %s",
			hex.EncodeToString(packed[16:20]),
			hex.EncodeToString(expectedAppDataLenBytes))
	}

	// Check application data content
	if !bytes.HasSuffix(packed, []byte("tls-server-end-point:test")) {
		t.Error("application data not found in packed output")
	}
}

func TestGSSChannelBindings_MD5Hash(t *testing.T) {
	cb := &GSSChannelBindings{
		InitiatorAddrType: 0,
		InitiatorAddress:  nil,
		AcceptorAddrType:  0,
		AcceptorAddress:   nil,
		ApplicationData:   []byte("tls-server-end-point:test"),
	}

	hash := cb.MD5Hash()

	// MD5 hash should be 16 bytes
	if len(hash) != 16 {
		t.Errorf("expected 16-byte hash, got %d bytes", len(hash))
	}

	// Verify hash is deterministic
	hash2 := cb.MD5Hash()
	if !bytes.Equal(hash, hash2) {
		t.Error("MD5 hash is not deterministic")
	}
}

func TestComputeTLSServerEndpoint_HashAlgorithm(t *testing.T) {
	cert := generateTestCert(t)

	cb := ComputeTLSServerEndpoint(cert)

	// Verify channel bindings were created
	if cb == nil {
		t.Fatal("ComputeTLSServerEndpoint returned nil")
	}

	// Verify application data starts with the expected prefix
	prefix := []byte("tls-server-end-point:")
	if len(cb.ApplicationData) <= len(prefix) {
		t.Errorf("application data too short: %d bytes", len(cb.ApplicationData))
	}

	if !bytes.HasPrefix(cb.ApplicationData, prefix) {
		t.Errorf("application data missing prefix, got: %s", cb.ApplicationData[:min(30, len(cb.ApplicationData))])
	}

	// Test certificate uses SHA256WithRSA, so hash should be SHA-256 (32 bytes)
	// Application data = prefix (21 bytes) + hash
	expectedLen := len(prefix) + 32 // SHA-256 = 32 bytes
	if len(cb.ApplicationData) != expectedLen {
		t.Errorf("expected application data length %d, got %d", expectedLen, len(cb.ApplicationData))
	}

	// Verify MD5 hash is 16 bytes
	md5Hash := cb.MD5Hash()
	if len(md5Hash) != 16 {
		t.Errorf("expected 16-byte MD5 hash, got %d bytes", len(md5Hash))
	}
}
