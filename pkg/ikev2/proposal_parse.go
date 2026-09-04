package ikev2

import (
	"fmt"
	"strings"
)

// ============================================================================
// 提议可配置化架构 (Proposal Configuration Architecture)
// ============================================================================
//
// 设计理念：
//   1. 总方法（拣货员）：读配置 → 按需调用子方法 → 组装提议链
//   2. 子方法（菜品）：每个提议一个独立方法，可复用
//   3. 用户配置有值：完全按用户配置点菜，互不干扰
//   4. 用户配置为空：总方法给一套默认大而全提议
//
// 字符串格式 (strongSwan 风格):
//
//   IKE: "aes256-sha256-modp2048"
//        "aes256-sha256-prfsha512-modp2048"  (可选 prf 覆盖)
//        "aes256gcm16-prfsha384-modp3072"
//        "aes128-sha1-modp1024"
//
//   ESP: "aes256-sha256"
//         "aes128gcm16"
//         "aes128-sha1"
//
// 解析规则:
//   aes256      → ENCR_AES_CBC, keylen=256
//   aes128      → ENCR_AES_CBC, keylen=128
//   aes256gcm16 → ENCR_AES_GCM_16, keylen=256
//   aes128gcm16 → ENCR_AES_GCM_16, keylen=128
//   aes256gcm12 → ENCR_AES_GCM_12, keylen=256
//   aes256gcm8  → ENCR_AES_GCM_8,  keylen=256
//   sha256      → AUTH_HMAC_SHA2_256_128 (IKE 同时设 PRF_HMAC_SHA2_256)
//   sha384      → AUTH_HMAC_SHA2_384_192 (IKE 同时设 PRF_HMAC_SHA2_384)
//   sha512      → AUTH_HMAC_SHA2_512_256 (IKE 同时设 PRF_HMAC_SHA2_512)
//   sha1        → AUTH_HMAC_SHA1_96      (IKE 同时设 PRF_HMAC_SHA1)
//   prfsha256   → PRF_HMAC_SHA2_256 (覆盖默认 PRF)
//   prfsha384   → PRF_HMAC_SHA2_384
//   prfsha512   → PRF_HMAC_SHA2_512
//   prfsha1     → PRF_HMAC_SHA1
//   modp2048    → MODP_2048_bit
//   modp1024    → MODP_1024_bit
//   modp3072    → MODP_3072_bit
//   modp4096    → MODP_4096_bit
// ============================================================================

// ---- 子方法：单个提议构建器 ----

// PropIKE_AES256_SHA256_MODP2048: AES-CBC-256 + SHA256 + MODP-2048
func PropIKE_AES256_SHA256_MODP2048(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoIKE, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 256)
	p.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	p.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	p.AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	return p
}

// PropIKE_AES256_SHA512_MODP2048: AES-CBC-256 + SHA512 + MODP-2048
func PropIKE_AES256_SHA512_MODP2048(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoIKE, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 256)
	p.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_512_256, 0)
	p.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_512, 0)
	p.AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	return p
}

// PropIKE_AES128_SHA256_MODP2048: AES-CBC-128 + SHA256 + MODP-2048
func PropIKE_AES128_SHA256_MODP2048(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoIKE, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	p.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	p.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	p.AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	return p
}

// PropIKE_AES128_SHA1_MODP1024: AES-CBC-128 + SHA1 + MODP-1024
func PropIKE_AES128_SHA1_MODP1024(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoIKE, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	p.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA1_96, 0)
	p.AddTransform(TransformTypePRF, PRF_HMAC_SHA1, 0)
	p.AddTransform(TransformTypeDH, MODP_1024_bit, 0)
	return p
}

// PropIKE_AES256GCM16_PRFSHA384_MODP3072: AES-GCM-256 + PRF-SHA384 + MODP-3072
func PropIKE_AES256GCM16_PRFSHA384_MODP3072(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoIKE, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_GCM_16, 256)
	p.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_384, 0)
	p.AddTransform(TransformTypeDH, MODP_3072_bit, 0)
	return p
}

// PropIKE_AES128GCM16_PRFSHA256_MODP2048: AES-GCM-128 + PRF-SHA256 + MODP-2048
func PropIKE_AES128GCM16_PRFSHA256_MODP2048(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoIKE, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_GCM_16, 128)
	p.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	p.AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	return p
}

// PropESP_AES256_SHA256: ESP AES-CBC-256 + SHA256
func PropESP_AES256_SHA256(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoESP, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 256)
	p.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	p.AddTransform(TransformTypeESN, 0, 0)
	return p
}

// PropESP_AES128_SHA256: ESP AES-CBC-128 + SHA256
func PropESP_AES128_SHA256(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoESP, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	p.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	p.AddTransform(TransformTypeESN, 0, 0)
	return p
}

// PropESP_AES256_SHA512: ESP AES-CBC-256 + SHA512
func PropESP_AES256_SHA512(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoESP, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 256)
	p.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_512_256, 0)
	p.AddTransform(TransformTypeESN, 0, 0)
	return p
}

// PropESP_AES128_SHA1: ESP AES-CBC-128 + SHA1
func PropESP_AES128_SHA1(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoESP, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	p.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA1_96, 0)
	p.AddTransform(TransformTypeESN, 0, 0)
	return p
}

// PropESP_AES256GCM16: ESP AES-GCM-256 (AEAD, 无独立完整性)
func PropESP_AES256GCM16(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoESP, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_GCM_16, 256)
	p.AddTransform(TransformTypeESN, 0, 0)
	return p
}

// PropESP_AES128GCM16: ESP AES-GCM-128 (AEAD, 无独立完整性)
func PropESP_AES128GCM16(num uint8, spi []byte) *Proposal {
	p := NewProposal(num, ProtoESP, spi)
	p.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_GCM_16, 128)
	p.AddTransform(TransformTypeESN, 0, 0)
	return p
}

// ---- 总方法：按配置拣货 ----

// ParseIKEProposals 从字符串列表解析 IKE 提议。
// 如果 specs 为空，返回默认大而全提议 (5 个，覆盖 GCM/CBC + SHA256/SHA1 + MODP 2048/1024)。
// 如果 specs 非空，完全按用户配置生成，互不干扰。
func ParseIKEProposals(specs []string, spi []byte) ([]*Proposal, error) {
	if len(specs) == 0 {
		// 默认兜底：大而全提议列表
		return []*Proposal{
			PropIKE_AES256GCM16_PRFSHA384_MODP3072(1, spi), // 高安全组
			PropIKE_AES128GCM16_PRFSHA256_MODP2048(2, spi), // 主流安全组 (VoWiFi 常用)
			PropIKE_AES256_SHA256_MODP2048(3, spi),         // 传统高安全组
			PropIKE_AES128_SHA256_MODP2048(4, spi),         // 传统主流组
			PropIKE_AES128_SHA1_MODP1024(5, spi),           // 远古兜底兼容组
		}, nil
	}

	proposals := make([]*Proposal, 0, len(specs))
	for i, spec := range specs {
		prop, err := parseIKEProposal(spec, uint8(i+1), spi)
		if err != nil {
			return nil, fmt.Errorf("IKE proposal #%d %q: %w", i+1, spec, err)
		}
		proposals = append(proposals, prop)
	}
	return proposals, nil
}

// ParseESPProposals 从字符串列表解析 ESP 提议。
// 如果 specs 为空，返回默认大而全提议 (4 个，覆盖 GCM/CBC + SHA256/SHA1)。
// 如果 specs 非空，完全按用户配置生成，互不干扰。
func ParseESPProposals(specs []string, spi []byte) ([]*Proposal, error) {
	if len(specs) == 0 {
		// 默认兜底：大而全提议列表
		return []*Proposal{
			PropESP_AES256GCM16(1, spi),   // 高安全 (AES-GCM-256)
			PropESP_AES128GCM16(2, spi),   // 主流安全 (AES-GCM-128)
			PropESP_AES128_SHA256(3, spi), // 传统主流 (AES-CBC-128 + SHA256)
			PropESP_AES128_SHA1(4, spi),   // 远古兜底兼容组 (AES-CBC-128 + SHA1)
		}, nil
	}

	proposals := make([]*Proposal, 0, len(specs))
	for i, spec := range specs {
		prop, err := parseESPProposal(spec, uint8(i+1), spi)
		if err != nil {
			return nil, fmt.Errorf("ESP proposal #%d %q: %w", i+1, spec, err)
		}
		proposals = append(proposals, prop)
	}
	return proposals, nil
}

// ---- 解析引擎 ----

// parseIKEProposal 解析单个 IKE 提议字符串。
// 格式: encr-integ[-prf]-dh，例如 "aes256-sha256-modp2048" 或 "aes256-sha256-prfsha512-modp2048"
func parseIKEProposal(spec string, num uint8, spi []byte) (*Proposal, error) {
	parts := strings.Split(strings.TrimSpace(strings.ToLower(spec)), "-")
	if len(parts) < 2 {
		return nil, fmt.Errorf("format: encr-integ[-prf]-dh, got %d parts", len(parts))
	}

	p := NewProposal(num, ProtoIKE, spi)

	// 解析加密算法 (必须)
	encrAlg, encrKeyLen, err := parseEncryption(parts[0])
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}
	p.AddTransformWithKeyLen(TransformTypeEncr, encrAlg, encrKeyLen)

	// 解析 DH 组 (必须，IKE 提议最后一个 part)
	dhAlg, err := parseDH(parts[len(parts)-1])
	if err != nil {
		return nil, fmt.Errorf("dh group: %w", err)
	}

	// 中间部分: integ 和可选的 prf
	var integFound, prfFound bool
	for _, part := range parts[1 : len(parts)-1] {
		if strings.HasPrefix(part, "prf") {
			prfAlg, err := parsePRF(part)
			if err != nil {
				return nil, fmt.Errorf("prf: %w", err)
			}
			p.AddTransform(TransformTypePRF, prfAlg, 0)
			prfFound = true
		} else {
			integAlg, err := parseIntegrity(part)
			if err != nil {
				return nil, fmt.Errorf("integrity: %w", err)
			}
			p.AddTransform(TransformTypeInteg, integAlg, 0)
			integFound = true
		}
	}

	// 如果没有显式 prf，从 integ 推导默认 prf
	if !prfFound && integFound {
		defaultPRF, err := defaultPRFFromInteg(parts[1])
		if err != nil {
			return nil, fmt.Errorf("derive prf from integ: %w", err)
		}
		p.AddTransform(TransformTypePRF, defaultPRF, 0)
	} else if !prfFound && !integFound {
		// AEAD 加密没有 integ，但仍需要 PRF
		// 默认使用 SHA256 PRF
		p.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	}

	// DH 组
	p.AddTransform(TransformTypeDH, dhAlg, 0)

	return p, nil
}

// parseESPProposal 解析单个 ESP 提议字符串。
// 格式: encr-integ，例如 "aes256-sha256" 或 "aes128gcm16"
func parseESPProposal(spec string, num uint8, spi []byte) (*Proposal, error) {
	parts := strings.Split(strings.TrimSpace(strings.ToLower(spec)), "-")
	if len(parts) < 1 {
		return nil, fmt.Errorf("format: encr[-integ], got %d parts", len(parts))
	}

	p := NewProposal(num, ProtoESP, spi)

	// 解析加密算法 (必须)
	encrAlg, encrKeyLen, err := parseEncryption(parts[0])
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}
	p.AddTransformWithKeyLen(TransformTypeEncr, encrAlg, encrKeyLen)

	// 解析完整性算法 (可选，AEAD 不需要)
	if len(parts) >= 2 {
		integAlg, err := parseIntegrity(parts[1])
		if err != nil {
			return nil, fmt.Errorf("integrity: %w", err)
		}
		p.AddTransform(TransformTypeInteg, integAlg, 0)
	}

	// ESN (默认 No ESN)
	p.AddTransform(TransformTypeESN, 0, 0)

	return p, nil
}

// ---- 算法解析辅助函数 ----

func parseEncryption(s string) (AlgorithmType, int, error) {
	switch s {
	case "aes256":
		return ENCR_AES_CBC, 256, nil
	case "aes128":
		return ENCR_AES_CBC, 128, nil
	case "aes256gcm16", "aesgcm16":
		return ENCR_AES_GCM_16, 256, nil
	case "aes128gcm16":
		return ENCR_AES_GCM_16, 128, nil
	case "aes256gcm12":
		return ENCR_AES_GCM_12, 256, nil
	case "aes256gcm8":
		return ENCR_AES_GCM_8, 256, nil
	default:
		return 0, 0, fmt.Errorf("unknown encryption %q", s)
	}
}

func parseIntegrity(s string) (AlgorithmType, error) {
	switch s {
	case "sha256":
		return AUTH_HMAC_SHA2_256_128, nil
	case "sha384":
		return AUTH_HMAC_SHA2_384_192, nil
	case "sha512":
		return AUTH_HMAC_SHA2_512_256, nil
	case "sha1":
		return AUTH_HMAC_SHA1_96, nil
	case "none", "":
		return AUTH_NONE, nil
	default:
		return 0, fmt.Errorf("unknown integrity %q", s)
	}
}

func parsePRF(s string) (AlgorithmType, error) {
	switch s {
	case "prfsha256":
		return PRF_HMAC_SHA2_256, nil
	case "prfsha384":
		return PRF_HMAC_SHA2_384, nil
	case "prfsha512":
		return PRF_HMAC_SHA2_512, nil
	case "prfsha1":
		return PRF_HMAC_SHA1, nil
	default:
		return 0, fmt.Errorf("unknown prf %q", s)
	}
}

func parseDH(s string) (AlgorithmType, error) {
	switch s {
	case "modp2048":
		return MODP_2048_bit, nil
	case "modp1024":
		return MODP_1024_bit, nil
	case "modp3072":
		return MODP_3072_bit, nil
	case "modp4096":
		return MODP_4096_bit, nil
	case "modp1536":
		return MODP_1536_bit, nil
	default:
		return 0, fmt.Errorf("unknown dh group %q", s)
	}
}

// defaultPRFFromInteg 从完整性算法推导默认 PRF
func defaultPRFFromInteg(integStr string) (AlgorithmType, error) {
	switch integStr {
	case "sha256":
		return PRF_HMAC_SHA2_256, nil
	case "sha384":
		return PRF_HMAC_SHA2_384, nil
	case "sha512":
		return PRF_HMAC_SHA2_512, nil
	case "sha1":
		return PRF_HMAC_SHA1, nil
	default:
		return PRF_HMAC_SHA2_256, nil
	}
}

// Describe 输出 strongSwan 风格的提议描述字符串
// 例如: "aes256gcm16-prfsha384-modp3072", "aes128-sha256-modp2048"
func (p *Proposal) Describe() string {
	var encr, integ, prf, dh string
	for _, t := range p.Transforms {
		switch t.Type {
		case TransformTypeEncr:
			encr = EncrToString(uint16(t.ID))
			for _, attr := range t.Attributes {
				if attr.Type == AttributeKeyLength {
					encr = fmt.Sprintf("%s%d", encr, attr.Val)
				}
			}
		case TransformTypeInteg:
			integ = IntegToString(uint16(t.ID))
		case TransformTypePRF:
			prf = PRFToString(uint16(t.ID))
		case TransformTypeDH:
			dh = DHToString(uint16(t.ID))
		case TransformTypeESN:
			// ESN 不在描述字符串中体现
		}
	}
	parts := []string{encr}
	if integ != "" && integ != "NONE" {
		parts = append(parts, integ)
	}
	if prf != "" {
		parts = append(parts, "prf"+prf)
	}
	if dh != "" && dh != "NONE" {
		parts = append(parts, dh)
	}
	return strings.Join(parts, "-")
}
