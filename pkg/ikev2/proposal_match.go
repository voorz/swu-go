package ikev2

// ProposalMatcher 用于多提议协商
// 根据本地支持的算法列表，从响应中选择最佳匹配
type ProposalMatcher struct {
	// 支持的加密算法 (按优先级排序)
	SupportedEncr []AlgorithmType
	// 支持的完整性算法
	SupportedInteg []AlgorithmType
	// 支持的 PRF 算法
	SupportedPRF []AlgorithmType
	// 支持的 DH 组
	SupportedDH []AlgorithmType
}

// DefaultProposalMatcher 返回默认的算法优先级 (类似于 strongSwan default proposals)
func DefaultProposalMatcher() *ProposalMatcher {
	return &ProposalMatcher{
		SupportedEncr: []AlgorithmType{
			// 高安全现代组 (首选)
			ENCR_AES_GCM_16,
			ENCR_AES_GCM_12,
			ENCR_AES_GCM_8,
			ENCR_AES_CCM_16,
			// 主流组
			ENCR_AES_CBC,
			ENCR_AES_CTR,
			// 老旧兼容兜底
			ENCR_3DES,
		},
		SupportedInteg: []AlgorithmType{
			AUTH_NONE, // AEAD 不需要独立完整性
			// SHA-2 系列
			AUTH_HMAC_SHA2_512_256,
			AUTH_HMAC_SHA2_384_192,
			AUTH_HMAC_SHA2_256_128,
			// 老旧与兜底系列
			AUTH_AES_XCBC_96,
			AUTH_HMAC_SHA1_96,
		},
		SupportedPRF: []AlgorithmType{
			PRF_HMAC_SHA2_512,
			PRF_HMAC_SHA2_384,
			PRF_HMAC_SHA2_256,
			PRF_AES128_XCBC,
			PRF_HMAC_SHA1,
		},
		SupportedDH: []AlgorithmType{
			// 安全组
			MODP_4096_bit,
			MODP_3072_bit,
			MODP_2048_bit, // IKEv2 最普及的安全底线
			// 兜底组 (不推荐但有时必须)
			MODP_1536_bit,
			MODP_1024_bit,
		},
	}
}

// MatchedAlgorithms 匹配结果
type MatchedAlgorithms struct {
	ProposalNum uint8
	ProtocolID  ProtocolID
	SPI         []byte
	Encr        AlgorithmType
	EncrKeyLen  uint16 // 从属性中获取
	Integ       AlgorithmType
	PRF         AlgorithmType
	DH          AlgorithmType
}

// SelectBestProposal 从 SA 中选择最佳匹配的提议
func (pm *ProposalMatcher) SelectBestProposal(sa *EncryptedPayloadSA) (*MatchedAlgorithms, error) {
	for _, prop := range sa.Proposals {
		matched := pm.matchProposal(prop)
		if matched != nil {
			return matched, nil
		}
	}
	return nil, nil // 无匹配
}

func (pm *ProposalMatcher) matchProposal(prop *Proposal) *MatchedAlgorithms {
	result := &MatchedAlgorithms{
		ProposalNum: prop.ProposalNum,
		ProtocolID:  prop.ProtocolID,
		SPI:         prop.SPI,
	}

	// 按变换类型分组
	encrFound := false
	integFound := false
	prfFound := false
	dhFound := false

	for _, t := range prop.Transforms {
		switch t.Type {
		case TransformTypeEncr:
			if pm.containsAlg(pm.SupportedEncr, t.ID) {
				result.Encr = t.ID
				encrFound = true
				// 提取密钥长度属性
				for _, attr := range t.Attributes {
					if attr.Type == AttributeKeyLength {
						result.EncrKeyLen = attr.Val
					}
				}
			}
		case TransformTypeInteg:
			if pm.containsAlg(pm.SupportedInteg, t.ID) {
				result.Integ = t.ID
				integFound = true
			}
		case TransformTypePRF:
			if pm.containsAlg(pm.SupportedPRF, t.ID) {
				result.PRF = t.ID
				prfFound = true
			}
		case TransformTypeDH:
			if pm.containsAlg(pm.SupportedDH, t.ID) {
				result.DH = t.ID
				dhFound = true
			}
		case TransformTypeESN:
			// ESN 通常接受 0 (不使用) 或 1 (使用)
		}
	}

	// IKE SA 需要: ENCR, PRF, (INTEG for non-AEAD), DH
	// Child SA (ESP) 需要: ENCR, (INTEG for non-AEAD), (ESN)
	if prop.ProtocolID == ProtoIKE {
		if encrFound && prfFound && dhFound {
			// AEAD 不需要独立的 INTEG
			if pm.isAEAD(result.Encr) || integFound {
				return result
			}
		}
	} else if prop.ProtocolID == ProtoESP {
		if encrFound {
			if pm.isAEAD(result.Encr) || integFound {
				return result
			}
		}
	}

	return nil
}

func (pm *ProposalMatcher) containsAlg(list []AlgorithmType, alg AlgorithmType) bool {
	for _, a := range list {
		if a == alg {
			return true
		}
	}
	return false
}

func (pm *ProposalMatcher) isAEAD(encr AlgorithmType) bool {
	switch encr {
	case ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16,
		ENCR_AES_CCM_8, ENCR_AES_CCM_12, ENCR_AES_CCM_16:
		return true
	default:
		return false
	}
}

// 注: CreateMultiProposalIKE 和 CreateMultiProposalESP 已删除。
// 提议生成统一走 proposal_parse.go 的 ParseIKEProposals / ParseESPProposals。
// 当配置为空时，ParseIKEProposals/ParseESPProposals 内联默认大而全提议列表。

// AddTransformWithKeyLen 添加带密钥长度属性的变换
func (p *Proposal) AddTransformWithKeyLen(tType TransformType, tID AlgorithmType, keyLen int) {
	t := &Transform{
		Type: tType,
		ID:   tID,
	}
	if keyLen > 0 {
		t.Attributes = append(t.Attributes, &TransformAttribute{
			Type: AttributeKeyLength,
			Val:  uint16(keyLen),
		})
	}
	p.Transforms = append(p.Transforms, t)
}
