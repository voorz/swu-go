package ikev2

import (
	"encoding/hex"
	"testing"
)

func TestSAPayloadSize(t *testing.T) {
	proposals, _ := ParseIKEProposals(nil, nil, true) // 默认大而全
	saPayload := &EncryptedPayloadSA{
		Proposals: proposals,
	}
	body, err := saPayload.Encode()
	if err != nil {
		t.Fatalf("SA Encode failed: %v", err)
	}
	t.Logf("SA body len: %d", len(body))
	t.Logf("SA body hex: %s", hex.EncodeToString(body))
	
// 默认 5 个 Proposal，字节数由实际编码决定
	t.Logf("Proposal count: %d", len(proposals))
	if len(proposals) != 5 {
		t.Errorf("Expected 5 default proposals, got %d", len(proposals))
	}
}
