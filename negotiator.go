package ntlmcbt

import (
	"fmt"

	"github.com/Azure/go-ntlmssp"
)

// Negotiator implements NTLM authentication with optional channel binding support.
// It wraps go-ntlmssp and injects MsvAvChannelBindings when channel bindings are provided.
type Negotiator struct {
	// ChannelBindings contains the computed channel binding token.
	// If nil, standard NTLM authentication is performed without CBT.
	ChannelBindings *GSSChannelBindings

	// DomainNeeded indicates whether the domain should be included in the response.
	// This is passed to go-ntlmssp's ProcessChallenge function.
	DomainNeeded bool
}

// NewNegotiator creates a new Negotiator with the provided channel bindings.
// It defaults to DomainNeeded=true, which matches standard Windows behavior.
func NewNegotiator(cb *GSSChannelBindings) *Negotiator {
	return &Negotiator{
		ChannelBindings: cb,
		DomainNeeded:    true,
	}
}

// Negotiate generates the initial NTLM NEGOTIATE_MESSAGE (Type 1).
// This message is sent to the server to begin the NTLM handshake.
func (n *Negotiator) Negotiate(domain, workstation string) ([]byte, error) {
	return ntlmssp.NewNegotiateMessage(domain, workstation)
}

// ChallengeResponse processes the server's CHALLENGE_MESSAGE (Type 2) and
// generates the AUTHENTICATE_MESSAGE (Type 3).
//
// If channel bindings are configured, the MsvAvChannelBindings AV_PAIR is
// injected into the response before computing the final message.
func (n *Negotiator) ChallengeResponse(challenge []byte, username, password string) ([]byte, error) {
	if n.ChannelBindings == nil {
		// No channel binding configured, use standard go-ntlmssp
		return ntlmssp.ProcessChallenge(challenge, username, password, n.DomainNeeded)
	}

	// Parse the challenge message to inject channel bindings
	modifiedChallenge, err := n.injectChannelBindings(challenge)
	if err != nil {
		return nil, fmt.Errorf("inject channel bindings: %w", err)
	}

	return ntlmssp.ProcessChallenge(modifiedChallenge, username, password, n.DomainNeeded)
}

// ChallengeResponseWithHash is like ChallengeResponse but uses a password hash
// instead of the plaintext password.
func (n *Negotiator) ChallengeResponseWithHash(challenge []byte, username, hash string) ([]byte, error) {
	if n.ChannelBindings == nil {
		return ntlmssp.ProcessChallengeWithHash(challenge, username, hash)
	}

	modifiedChallenge, err := n.injectChannelBindings(challenge)
	if err != nil {
		return nil, fmt.Errorf("inject channel bindings: %w", err)
	}

	return ntlmssp.ProcessChallengeWithHash(modifiedChallenge, username, hash)
}

// injectChannelBindings modifies the challenge message to include channel bindings
// in the TargetInfo field. This uses the vadimi/go-ntlm library for message
// parsing since go-ntlmssp doesn't expose this functionality.
func (n *Negotiator) injectChannelBindings(challenge []byte) ([]byte, error) {
	// Parse challenge message
	cm, err := parseChallengeMessage(challenge)
	if err != nil {
		return nil, fmt.Errorf("parse challenge: %w", err)
	}

	// Inject channel binding hash into TargetInfo
	cbHash := n.ChannelBindings.MD5Hash()
	cm.injectChannelBindings(cbHash)

	// Re-serialize the modified challenge
	return cm.Bytes()
}
