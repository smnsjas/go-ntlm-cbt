package ntlmcbt

import (
	"crypto"
	"crypto/md5"
	"crypto/x509"
	"encoding/binary"
)

// GSSChannelBindings represents the RFC 2744 gss_channel_bindings_struct.
// For TLS server endpoint channel bindings, only ApplicationData is populated.
type GSSChannelBindings struct {
	// InitiatorAddrType is the address type of the initiator (typically 0/unspecified).
	InitiatorAddrType uint32
	// InitiatorAddress is the initiator's address (typically empty for TLS bindings).
	InitiatorAddress []byte
	// AcceptorAddrType is the address type of the acceptor (typically 0/unspecified).
	AcceptorAddrType uint32
	// AcceptorAddress is the acceptor's address (typically empty for TLS bindings).
	AcceptorAddress []byte
	// ApplicationData contains the channel binding data (e.g., "tls-server-end-point:<hash>").
	ApplicationData []byte
}

// Pack serializes the channel bindings to wire format (little-endian).
// This format is compatible with Windows SEC_CHANNEL_BINDINGS structure.
func (cb *GSSChannelBindings) Pack() []byte {
	// Calculate total size
	size := 4 + 4 + len(cb.InitiatorAddress) + // InitiatorAddrType + Length + Data
		4 + 4 + len(cb.AcceptorAddress) + // AcceptorAddrType + Length + Data
		4 + len(cb.ApplicationData) // Length + Data

	buf := make([]byte, 0, size)

	// Initiator
	buf = binary.LittleEndian.AppendUint32(buf, cb.InitiatorAddrType)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(cb.InitiatorAddress)))
	buf = append(buf, cb.InitiatorAddress...)

	// Acceptor
	buf = binary.LittleEndian.AppendUint32(buf, cb.AcceptorAddrType)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(cb.AcceptorAddress)))
	buf = append(buf, cb.AcceptorAddress...)

	// Application Data
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(cb.ApplicationData)))
	buf = append(buf, cb.ApplicationData...)

	return buf
}

// MD5Hash returns the MD5 hash of the packed channel bindings.
// This is the value used in NTLM's MsvAvChannelBindings AV_PAIR.
func (cb *GSSChannelBindings) MD5Hash() []byte {
	hasher := md5.New()
	hasher.Write(cb.Pack())
	return hasher.Sum(nil)
}

// ComputeTLSServerEndpoint creates channel bindings from a TLS server certificate
// using the tls-server-end-point method defined in RFC 5929.
//
// The hash algorithm is determined by the certificate's signature algorithm:
//   - MD5 or SHA-1 signatures → use SHA-256 (per RFC 5929 Section 4.1)
//   - SHA-384 signatures → use SHA-384
//   - SHA-512 signatures → use SHA-512
//   - All others → use SHA-256
func ComputeTLSServerEndpoint(cert *x509.Certificate) *GSSChannelBindings {
	// Determine hash algorithm per RFC 5929
	hashType := crypto.SHA256

	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		hashType = crypto.SHA512
		// MD5, SHA-1, and all others default to SHA-256
	}

	// Hash the DER-encoded certificate
	hasher := hashType.New()
	hasher.Write(cert.Raw)
	certHash := hasher.Sum(nil)

	// Build application data: "tls-server-end-point:" + hash
	prefix := []byte("tls-server-end-point:")
	appData := make([]byte, len(prefix)+len(certHash))
	copy(appData, prefix)
	copy(appData[len(prefix):], certHash)

	return &GSSChannelBindings{
		InitiatorAddrType: 0,
		InitiatorAddress:  nil,
		AcceptorAddrType:  0,
		AcceptorAddress:   nil,
		ApplicationData:   appData,
	}
}
