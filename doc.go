// Package ntlmcbt provides NTLM authentication with Channel Binding Token (CBT)
// support for Extended Protection for Authentication (EPA).
//
// This package wraps go-ntlmssp and injects MsvAvChannelBindings into the NTLM
// AUTHENTICATE_MESSAGE, enabling authentication to EPA-protected servers.
//
// Channel binding tokens are computed per RFC 5929 using the tls-server-end-point
// method, which hashes the server's TLS certificate.
//
// # Usage
//
// After establishing a TLS connection, extract the server certificate and create
// a channel binding:
//
//	cert := tlsConn.ConnectionState().PeerCertificates[0]
//	cb := ntlmcbt.ComputeTLSServerEndpoint(cert)
//
// Then use the Negotiator to perform NTLM authentication:
//
//	nego := &ntlmcbt.Negotiator{ChannelBindings: cb}
//	negotiateMsg, _ := nego.Negotiate("DOMAIN", "WORKSTATION")
//	// ... send negotiateMsg, receive challengeMsg ...
//	authMsg, _ := nego.ChallengeResponse(challengeMsg, "user", "password")
package ntlmcbt
