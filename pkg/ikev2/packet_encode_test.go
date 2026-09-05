package ikev2

import (
	"encoding/hex"
	"testing"
)

func TestFullPacketEncode(t *testing.T) {
	proposals, _ := ParseIKEProposals(nil, nil, true) // 默认大而全
	saPayload := &EncryptedPayloadSA{
		Proposals: proposals,
	}
	
	kePayload := &EncryptedPayloadKE{
		DHGroup: 14,
		KEData:  make([]byte, 256), // fake KE data
	}
	
	noncePayload := &EncryptedPayloadNonce{
		NonceData: make([]byte, 32),
	}
	
	fragNotify := &EncryptedPayloadNotify{
		ProtocolID:  0,
		NotifyType: IKEV2_FRAGMENTATION_SUPPORTED,
	}
	
	payloads := []Payload{saPayload, kePayload, noncePayload, fragNotify}
	
	packet := NewIKEPacket()
	packet.Header.SPIi = 0x0102030405060708
	packet.Header.Version = 0x20
	packet.Header.ExchangeType = IKE_SA_INIT
	packet.Header.Flags = FlagInitiator
	packet.Header.MessageID = 0
	packet.Payloads = payloads
	
	data, err := packet.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	
	t.Logf("Total packet len: %d", len(data))
	t.Logf("SA payload at offset 28: type=0x%02x", data[16])
	
	// 检查 SA payload header
	saNext := data[28]
	saFlags := data[29]
	saLen := uint16(data[30])<<8 | uint16(data[31])
	t.Logf("SA payload: next=0x%02x flags=0x%02x len=%d", saNext, saFlags, saLen)
	
	// SA body 大小由实际编码决定（5 个默认提议）
	saLen := uint16(data[30])<<8 | uint16(data[31])
	t.Logf("SA payload len: %d", saLen)
	if saLen < 4 {
		t.Errorf("SA payload too small: %d", saLen)
	}
	
	t.Logf("Full hex (first 200): %s", hex.EncodeToString(data[:200]))
}
