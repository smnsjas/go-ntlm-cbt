# go-ntlm-cbt

A Go library that extends [go-ntlmssp](https://github.com/Azure/go-ntlmssp) with Channel Binding Token (CBT) support for Extended Protection for Authentication (EPA).

## Overview

When Extended Protection for Authentication (EPA) is enabled on Windows servers, NTLM authentication requires a Channel Binding Token (CBT) derived from the TLS server certificate. Without CBT, authentication fails with errors like "The token supplied to the function is invalid."

This library wraps `go-ntlmssp` and injects the `MsvAvChannelBindings` AV_PAIR into the NTLM AUTHENTICATE_MESSAGE, enabling authentication to EPA-protected servers.

## Features

- **RFC 5929 Compliant**: Implements `tls-server-end-point` channel binding.
- **Drop-in Enhancement**: Works alongside `go-ntlmssp` without forking it.
- **Zero Additional Dependencies**: Only depends on `go-ntlmssp` and the Go standard library.

## Installation

```bash
go get github.com/smnsjas/go-ntlm-cbt
```

## Usage

```go
import (
    "crypto/tls"
    "crypto/x509"
    
    ntlmcbt "github.com/smnsjas/go-ntlm-cbt"
)

// After TLS handshake, get the server certificate
cert := tlsConn.ConnectionState().PeerCertificates[0]

// Compute channel bindings
cb := ntlmcbt.ComputeTLSServerEndpoint(cert)

// Create the negotiator
negotiator := ntlmcbt.NewNegotiator(cb)

// 1. Generate Negotiate Message (Type 1)
negotiateMsg, err := negotiator.Negotiate("DOMAIN", "WORKSTATION")
if err != nil {
    // handle error
}

// ... send negotiateMsg to server, receive challengeMsg ...

// 2. Generate Authenticate Message (Type 3)
authMsg, err := negotiator.ChallengeResponse(challengeMsg, "username", "password")
if err != nil {
    // handle error
}
```

## Why Extended Protection Matters

Extended Protection for Authentication (EPA) defends against **NTLM Relay Attacks** (Credential Relaying).

In a typical relay attack, an attacker intercepts an NTLM handshake and forwards it to a target server. The server thinks it's talking to the legitimate client.

**Channel Binding Tokens (CBT)** prevent this by cryptographically binding the NTLM authentication to the underlying TLS connection.

1. The client calculates a hash of the server's TLS certificate (the CBT).
2. The client embeds this CBT inside the encrypted NTLM message.
3. The server validates that the CBT in the NTLM message matches its own TLS certificate.

If an attacker relays the traffic over their own TLS connection, the CBTs won't match, and the server rejects the authentication.

## How It Works

1. **Computes Channel Binding Token**: Hashes the server's TLS certificate per RFC 5929.
2. **Constructs GSS Channel Bindings**: Builds the RFC 2744 `gss_channel_bindings_struct`.
3. **Injects AV_PAIR**: Adds `MsvAvChannelBindings` (AvId=0x000A) to the NTLM Type 3 message.
4. **Recomputes MIC**: Updates the Message Integrity Code after modification.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [go-ntlmssp](https://github.com/Azure/go-ntlmssp) - The underlying NTLM implementation.
- [pyspnego](https://github.com/jborean93/pyspnego) - Reference implementation for channel bindings.
- [ntlmnego](https://github.com/racktopsystems/ntlmnego) - Inspiration for the interposition pattern.
