package swu

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"

	"github.com/voorz/swu-go/pkg/eap"
	"github.com/voorz/swu-go/pkg/logger"
	"github.com/voorz/swu-go/pkg/sim"
)

// buildChallengeResponseAttrs constructs the EAP-AKA Challenge Response
// attributes based on the configured AKAChallengeMode:
//
//   - "standard" (default): AT_RES + echo non-standard attrs + AT_RESULT_IND(if present) + AT_MAC
//   - "minimal":             AT_RES + AT_CHECKCODE_EXT(0x86, echo ePDG value) + AT_MAC (no echo of other attrs, no AT_RESULT_IND)
//   - "checkcode":           AT_RES + AT_CHECKCODE_EXT(0x86) + AT_MAC (no echo, no AT_RESULT_IND)
//   - "omit":                AT_RES + AT_MAC (no echo, no AT_CHECKCODE, no AT_RESULT_IND)
//
// The "minimal" mode is used by 3HK and other ePDGs that expect a minimal
// attribute set with AT_CHECKCODE(0x86) echoed from the ePDG Challenge.
// It differs from "checkcode" in that the AT_CHECKCODE is always sourced
// from the ePDG Challenge value (never falls back to local SHA-1(IMEI)).
//
// The "checkcode" mode also uses non-standard attribute type 0x86 (134).
// When the ePDG sends AT_0x86 in the Challenge, it contains a device-bound
// checkcode value (not a random nonce — the value stays constant across
// different RAND/AUTN for the same device). The client MUST echo back the
// exact AT_0x86 value from the Challenge. If the client sends a self-computed
// SHA-1(IMEI) instead, the ePDG will reject with EAP Failure (Code 4).
//
// If the Challenge does not contain AT_0x86, the client falls back to
// computing SHA-1(IMEI) as the checkcode value.
func (s *Session) buildChallengeResponseAttrs(
	attrs map[uint8]*eap.Attribute,
	res []byte,
	kAut []byte,
	pkt *eap.EAPPacket,
) []byte {
	mode := s.cfg.AKAChallengeMode
	if mode == "" {
		mode = "standard"
	}

	s.Logger.Debug(s.pfx("EAP-AKA Challenge Response 模式"),
		logger.String("challenge_mode", mode))

	respAttrs := []byte{}

	// AT_RES — always present
	resBits := make([]byte, 2)
	binary.BigEndian.PutUint16(resBits, uint16(len(res)*8))
	resValue := append(resBits, res...)
	atRes := &eap.Attribute{Type: eap.AT_RES, Value: resValue}
	respAttrs = append(respAttrs, atRes.Encode()...)

	switch mode {
	case "minimal":
		// Minimal mode: AT_RES + AT_CHECKCODE(echo) + AT_MAC only.
		// Used by 3HK ePDG. The AT_CHECKCODE(0x86) value is always sourced
		// from the ePDG Challenge — never falls back to local SHA-1(IMEI).
		// If the Challenge does not contain AT_0x86, AT_CHECKCODE is omitted.
		if epdgAttr, ok := attrs[0x86]; ok && len(epdgAttr.Value) >= 2 {
			atCC := &eap.Attribute{Type: 0x86, Value: epdgAttr.Value}
			respAttrs = append(respAttrs, atCC.Encode()...)
			s.Logger.Debug(s.pfx("AT_CHECKCODE(0x86) 回显 ePDG 值"),
				logger.String("epdg_value_hex", hex.EncodeToString(epdgAttr.Value)),
				logger.Int("value_len", len(epdgAttr.Value)),
				logger.String("attr_type", "0x86"),
				logger.String("source", "epdg_echo"))
		} else {
			s.Logger.Warn(s.pfx("challenge_mode=minimal 但 ePDG 未发送 AT_0x86，跳过 AT_CHECKCODE"))
		}

	case "checkcode":
		// 3HK non-standard AT_CHECKCODE: type=0x86(134).
		// The ePDG sends AT_0x86 in the Challenge with a device-bound checkcode
		// value. The client MUST echo back the exact same AT_0x86 value.
		// If the Challenge does not contain AT_0x86, fall back to SHA-1(IMEI).
		if epdgAttr, ok := attrs[0x86]; ok && len(epdgAttr.Value) >= 2 {
			// Echo ePDG's AT_0x86 value directly
			atCC := &eap.Attribute{Type: 0x86, Value: epdgAttr.Value}
			respAttrs = append(respAttrs, atCC.Encode()...)
			s.Logger.Debug(s.pfx("AT_CHECKCODE(0x86) 回显 ePDG 值"),
				logger.String("epdg_value_hex", hex.EncodeToString(epdgAttr.Value)),
				logger.Int("value_len", len(epdgAttr.Value)),
				logger.String("attr_type", "0x86"),
				logger.String("source", "epdg_echo"))
		} else {
			// Fallback: compute SHA-1(IMEI) when ePDG didn't send AT_0x86
			checkcode := s.computeCheckcode()
			if len(checkcode) > 0 {
				ccValue := make([]byte, 2+len(checkcode))
				ccValue[0] = 0x00
				ccValue[1] = 0x00
				copy(ccValue[2:], checkcode)
				atCC := &eap.Attribute{Type: 0x86, Value: ccValue}
				respAttrs = append(respAttrs, atCC.Encode()...)
				s.Logger.Debug(s.pfx("AT_CHECKCODE(0x86) 使用本地 SHA1(IMEI)"),
					logger.String("checkcode_hex", hex.EncodeToString(checkcode)),
					logger.Int("checkcode_len", len(checkcode)),
					logger.String("attr_type", "0x86"),
					logger.String("source", "local_sha1_imei"))
			} else {
				s.Logger.Warn(s.pfx("challenge_mode=checkcode 但无法获取 IMEI，跳过 AT_CHECKCODE(0x86)"))
			}
		}

	case "omit":
		// No AT_CHECKCODE, no echo, no AT_RESULT_IND

	case "standard":
		fallthrough
	default:
		// Echo non-standard attributes (0x86/134 etc.)
		for attrType, attrVal := range attrs {
			if attrType == eap.AT_RAND || attrType == eap.AT_AUTN || attrType == eap.AT_MAC ||
				attrType == eap.AT_RESULT_IND || attrType == eap.AT_RES {
				continue
			}
			s.Logger.Debug(s.pfx("Challenge Response 回显非标属性"),
				logger.Int("attr_type", int(attrType)),
				logger.Int("attr_value_len", len(attrVal.Value)))
			echoAttr := &eap.Attribute{Type: attrType, Value: attrVal.Value}
			respAttrs = append(respAttrs, echoAttr.Encode()...)
		}

		// AT_RESULT_IND (if present in Challenge)
		if _, ok := attrs[eap.AT_RESULT_IND]; ok {
			atResultInd := &eap.Attribute{Type: eap.AT_RESULT_IND, Value: []byte{0, 0}}
			respAttrs = append(respAttrs, atResultInd.Encode()...)
		}
	}

	return respAttrs
}

// computeCheckcode returns the SHA-1 hash of the IMEI, truncated to 20 bytes.
// Returns nil if IMEI is unavailable.
func (s *Session) computeCheckcode() []byte {
	var imei string
	// Priority 1: explicit IMEI in Config (passed from vohive-next device profile)
	if s.cfg.IMEI != "" {
		imei = s.cfg.IMEI
	}
	// Priority 2: SIM provider implements IMEIProvider
	if imei == "" {
		if p, ok := s.cfg.SIM.(sim.IMEIProvider); ok {
			if val, err := p.GetIMEI(); err == nil && val != "" {
				imei = val
			}
		}
	}
	if imei == "" {
		// Fallback: use configured IMSI as identity for checkcode
		// (some ePDGs accept IMSI-derived checkcode when IMEI is unavailable)
		imsi, _ := s.cfg.SIM.GetIMSI()
		if imsi == "" {
			imsi = s.cfg.IMSI
		}
		if imsi != "" {
			imei = imsi
		}
	}
	if imei == "" {
		return nil
	}
	h := sha1.Sum([]byte(imei))
	return h[:]
}
