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

// Use with NTLM authentication
authenticator := ntlmcbt.NewAuthenticator("DOMAIN", "username", "password", cb)
```

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
