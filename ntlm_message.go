package ntlmcbt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// NTLM message type constants
const (
	ntlmSignature   = "NTLMSSP\x00"
	typeChallengeID = 2
)

// AV_PAIR IDs from MS-NLMP
const (
	avIDMsvAvEOL             = 0x0000
	avIDMsvAvNbComputerName  = 0x0001
	avIDMsvAvNbDomainName    = 0x0002
	avIDMsvAvDnsComputerName = 0x0003
	avIDMsvAvDnsDomainName   = 0x0004
	avIDMsvAvDnsTreeName     = 0x0005
	avIDMsvAvFlags           = 0x0006
	avIDMsvAvTimestamp       = 0x0007
	avIDMsvAvSingleHost      = 0x0008
	avIDMsvAvTargetName      = 0x0009
	avIDMsvAvChannelBindings = 0x000A
)

// challengeMessage represents a parsed NTLM CHALLENGE_MESSAGE (Type 2).
// We only parse the fields we need to modify.
type challengeMessage struct {
	raw        []byte
	targetInfo []avPair
	// Offsets for TargetInfo in the raw message
	targetInfoOffset uint32
	targetInfoLen    uint16
	// Header offset where TargetInfo descriptor lives
	targetInfoDescriptorOffset int
}

// avPair represents an AV_PAIR structure from MS-NLMP.
type avPair struct {
	ID    uint16
	Value []byte
}

// parseChallengeMessage parses an NTLM Type 2 challenge message.
func parseChallengeMessage(data []byte) (*challengeMessage, error) {
	if len(data) < 32 {
		return nil, errors.New("challenge message too short")
	}

	// Verify signature
	if !bytes.Equal(data[:8], []byte(ntlmSignature)) {
		return nil, errors.New("invalid NTLM signature")
	}

	// Verify message type
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != typeChallengeID {
		return nil, fmt.Errorf("not a challenge message (type %d)", msgType)
	}

	cm := &challengeMessage{
		raw: data,
	}

	// Parse TargetInfo if present (offset 40)
	// Structure: Len (2), MaxLen (2), Offset (4)
	if len(data) >= 48 {
		cm.targetInfoLen = binary.LittleEndian.Uint16(data[40:42])
		cm.targetInfoOffset = binary.LittleEndian.Uint32(data[44:48])
		cm.targetInfoDescriptorOffset = 40

		if cm.targetInfoLen > 0 && int(cm.targetInfoOffset+uint32(cm.targetInfoLen)) <= len(data) {
			cm.targetInfo = parseAVPairs(data[cm.targetInfoOffset : cm.targetInfoOffset+uint32(cm.targetInfoLen)])
		}
	}

	return cm, nil
}

// parseAVPairs parses a sequence of AV_PAIR structures.
func parseAVPairs(data []byte) []avPair {
	var pairs []avPair
	offset := 0

	for offset+4 <= len(data) {
		id := binary.LittleEndian.Uint16(data[offset : offset+2])
		length := binary.LittleEndian.Uint16(data[offset+2 : offset+4])

		if id == avIDMsvAvEOL {
			pairs = append(pairs, avPair{ID: id, Value: nil})
			break
		}

		if offset+4+int(length) > len(data) {
			break
		}

		pairs = append(pairs, avPair{
			ID:    id,
			Value: data[offset+4 : offset+4+int(length)],
		})
		offset += 4 + int(length)
	}

	return pairs
}

// injectChannelBindings adds the MsvAvChannelBindings AV_PAIR to the message.
func (cm *challengeMessage) injectChannelBindings(cbHash []byte) {
	// Remove existing EOL if present
	newPairs := make([]avPair, 0, len(cm.targetInfo)+2)
	for _, pair := range cm.targetInfo {
		if pair.ID != avIDMsvAvEOL {
			newPairs = append(newPairs, pair)
		}
	}

	// Add channel bindings (must be 16 bytes - MD5 hash)
	if len(cbHash) != 16 {
		// Pad or truncate to 16 bytes
		padded := make([]byte, 16)
		copy(padded, cbHash)
		cbHash = padded
	}
	newPairs = append(newPairs, avPair{ID: avIDMsvAvChannelBindings, Value: cbHash})

	// Add EOL marker
	newPairs = append(newPairs, avPair{ID: avIDMsvAvEOL, Value: nil})

	cm.targetInfo = newPairs
}

// bytes re-serializes the challenge message with modified TargetInfo.
func (cm *challengeMessage) bytes() ([]byte, error) {
	// Serialize new TargetInfo
	newTargetInfo := serializeAVPairs(cm.targetInfo)

	// Calculate size difference
	oldLen := int(cm.targetInfoLen)
	newLen := len(newTargetInfo)
	diff := newLen - oldLen

	// Build new message
	// Copy everything before TargetInfo data
	var result []byte
	targetInfoDataStart := int(cm.targetInfoOffset)

	if targetInfoDataStart > len(cm.raw) {
		// TargetInfo was at the end of the message
		result = make([]byte, len(cm.raw)+diff)
		copy(result, cm.raw)
	} else {
		// Need to rebuild with new TargetInfo
		result = make([]byte, 0, len(cm.raw)+diff)

		// Copy header and everything before TargetInfo
		result = append(result, cm.raw[:targetInfoDataStart]...)

		// Insert new TargetInfo
		result = append(result, newTargetInfo...)

		// Copy everything after old TargetInfo
		afterTargetInfo := targetInfoDataStart + oldLen
		if afterTargetInfo < len(cm.raw) {
			result = append(result, cm.raw[afterTargetInfo:]...)
		}
	}

	// Update TargetInfo length fields in the header
	// TargetInfo descriptor is at offset 40: Len (2), MaxLen (2), Offset (4)
	if len(result) >= 48 {
		// #nosec G115 -- newLen is bounded by NTLM message size (<64KB)
		binary.LittleEndian.PutUint16(result[40:42], uint16(newLen))
		// #nosec G115 -- newLen is bounded by NTLM message size (<64KB)
		binary.LittleEndian.PutUint16(result[42:44], uint16(newLen))
	}

	return result, nil
}

// serializeAVPairs converts AV_PAIR slice back to wire format.
func serializeAVPairs(pairs []avPair) []byte {
	var buf bytes.Buffer

	for _, pair := range pairs {
		// binary.Write to bytes.Buffer never fails
		_ = binary.Write(&buf, binary.LittleEndian, pair.ID)
		// #nosec G115 -- AV_PAIR values are bounded by NTLM spec (<64KB)
		_ = binary.Write(&buf, binary.LittleEndian, uint16(len(pair.Value)))
		_, _ = buf.Write(pair.Value)
	}

	return buf.Bytes()
}
