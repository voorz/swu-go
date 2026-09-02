package ikev2

import (
	"encoding/hex"
	"testing"
)

func TestFullPacketEncode(t *testing.T) {
	proposals := CreateMultiProposalIKE(nil)
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
	
	// SA body should be 132, total SA payload should be 136
	if saLen != 136 {
		t.Errorf("SA payload len should be 136, got %d", saLen)
	}
	
	// 检查 KE payload header (at offset 28+136=164)
	keNext := data[164]
	keFlags := data[165]
	keLen := uint16(data[166])<<8 | uint16(data[167])
	t.Logf("KE payload: next=0x%02x flags=0x%02x len=%d", keNext, keFlags, keLen)
	
	t.Logf("Full hex (first 200): %s", hex.EncodeToString(data[:200]))
}
