package ikev2

import (
	"encoding/hex"
	"testing"
)

func TestSAPayloadSize(t *testing.T) {
	proposals := CreateMultiProposalIKE(nil)
	saPayload := &EncryptedPayloadSA{
		Proposals: proposals,
	}
	body, err := saPayload.Encode()
	if err != nil {
		t.Fatalf("SA Encode failed: %v", err)
	}
	t.Logf("SA body len: %d", len(body))
	t.Logf("SA body hex: %s", hex.EncodeToString(body))
	
	// 预期 3 个 Proposal 各 44 字节 = 132
	if len(body) != 132 {
		t.Errorf("SA body should be 132 bytes, got %d", len(body))
	}
}
