package ntlmcbt

import (
	"bytes"
	"testing"
)

func TestParseChallengeMessage(t *testing.T) {
	// Sample NTLM Type 2 message (from a real capture or constructed)
	// This generic one just has the header and signature
	baseMsg := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, // Signature
		2, 0, 0, 0, // Type 2
		0, 0, 0, 0, 0, 0, 0, 0, // TargetName fields (len, max, off)
		0, 0, 0, 0, // Flags
		0, 0, 0, 0, 0, 0, 0, 0, // Challenge
		0, 0, 0, 0, 0, 0, 0, 0, // Context
		0, 0, 0, 0, 0, 0, 0, 0, // TargetInfo fields (len, max, off)
	}

	t.Run("ValidBasicMessage", func(t *testing.T) {
		cm, err := parseChallengeMessage(baseMsg)
		if err != nil {
			t.Fatalf("parseChallengeMessage failed: %v", err)
		}
		if cm == nil {
			t.Fatal("returned nil challengeMessage")
		}
		if cm.targetInfoLen != 0 {
			t.Errorf("expected 0 target info len, got %d", cm.targetInfoLen)
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		badMsg := make([]byte, len(baseMsg))
		copy(badMsg, baseMsg)
		badMsg[0] = 'X'
		_, err := parseChallengeMessage(badMsg)
		if err == nil {
			t.Error("expected error for invalid signature, got nil")
		}
	})

	t.Run("ShortMessage", func(t *testing.T) {
		_, err := parseChallengeMessage(baseMsg[:10])
		if err == nil {
			t.Error("expected error for short message, got nil")
		}
	})
}

// Helper to construct a message with TargetInfo
func makeMessageWithTargetInfo(info []byte) []byte {
	// Standard header size is 48 bytes (up to TargetInfo fields)
	// We need to point TargetInfo offset to where data starts (e.g., 48)
	baseLen := 48
	msg := make([]byte, baseLen+len(info))

	copy(msg, []byte("NTLMSSP\x00"))
	msg[8] = 2 // Type 2

	// Set TargetInfo fields (offset 40)
	// Len (2), MaxLen (2), Offset (4)
	infoLen := uint16(len(info))
	msg[40] = byte(infoLen)
	msg[41] = byte(infoLen >> 8)
	msg[42] = msg[40] // MaxLen
	msg[43] = msg[41]

	offset := uint32(baseLen)
	msg[44] = byte(offset)
	msg[45] = byte(offset >> 8)
	msg[46] = byte(offset >> 16)
	msg[47] = byte(offset >> 24)

	copy(msg[baseLen:], info)
	return msg
}

func TestInjectChannelBindings(t *testing.T) {
	// Create a message with some existing AV_PAIRs
	// MsvAvNbDomainName (2) = "DOMAIN"
	// MsvAvEOL (0)
	existingInfo := []byte{
		2, 0, 12, 0, 'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0, // Domain
		0, 0, 0, 0, // EOL
	}

	msgData := makeMessageWithTargetInfo(existingInfo)
	cm, err := parseChallengeMessage(msgData)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Inject Hash
	hash := make([]byte, 16)
	for i := range hash {
		hash[i] = byte(i)
	}

	cm.injectChannelBindings(hash)

	newMsgBytes, err := cm.Bytes()
	if err != nil {
		t.Fatalf("Bytes() failed: %v", err)
	}

	// Parse back to verify
	cm2, err := parseChallengeMessage(newMsgBytes)
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}

	// Verify we have the new AV_PAIR
	found := false
	for _, pair := range cm2.targetInfo {
		if pair.ID == avIDMsvAvChannelBindings {
			found = true
			if !bytes.Equal(pair.Value, hash) {
				t.Errorf("hash mismatch in injected pair")
			}
		}
	}

	if !found {
		t.Error("MsvAvChannelBindings not found in re-parsed message")
	}
}

func BenchmarkInjectChannelBindings(b *testing.B) {
	existingInfo := []byte{
		2, 0, 12, 0, 'D', 0, 'O', 0, 'M', 0, 'A', 0, 'I', 0, 'N', 0,
		1, 0, 12, 0, 'S', 0, 'E', 0, 'R', 0, 'V', 0, 'E', 0, 'R', 0,
		0, 0, 0, 0,
	}
	msgData := makeMessageWithTargetInfo(existingInfo)
	hash := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cm, _ := parseChallengeMessage(msgData)
		cm.injectChannelBindings(hash)
		_, _ = cm.Bytes()
	}
}
