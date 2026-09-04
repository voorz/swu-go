package swu

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/voorz/swu-go/pkg/crypto"
	"github.com/voorz/swu-go/pkg/eap"
	"github.com/voorz/swu-go/pkg/ikev2"
	"github.com/voorz/swu-go/pkg/ipsec"
	"github.com/voorz/swu-go/pkg/logger"
	"github.com/voorz/swu-go/pkg/sim"
	"go.uber.org/zap"
)

func (s *Session) buildIKEAuthInitPayloads() ([]ikev2.Payload, error) {
	// RFC 7296 §2.2: 标准 IKEv2 EAP 流程
	// Init -> SK { IDi, IDr, SAi2, TSi, TSr, N(MOBIKE), N(TICKET_REQUEST), N(INITIAL_CONTACT) }
	// 注意: 第一包不包含 AUTH payload（EAP 完成后才发送最终 AUTH）
	// 注意: 不发送 N(EAP_ONLY_AUTHENTICATION)，部分 ePDG 不支持 RFC 5998 会直接返回 AUTHENTICATION_FAILED

	// 1. IDi
	var nai string
	if s.cfg.FastReauthID != "" {
		nai = s.cfg.FastReauthID
		s.Logger.Info(s.pfx("IKE_AUTH: 探测到缓存的 FastReauthID 假名，替代 IMSI 暴露身份"), logger.String("nai", nai))
	} else {
		imsi, err := s.cfg.SIM.GetIMSI()
		if err != nil || imsi == "" {
			imsi = s.cfg.IMSI // fallback: 使用 Config 中预设的 IMSI
		}
		nai = buildNAI(imsi, s.cfg)
	}
	idPayload := &ikev2.EncryptedPayloadID{
		IDType:      ikev2.ID_RFC822_ADDR,
		IDData:      []byte(nai),
		IsInitiator: true,
	}
	idrPayload := &ikev2.EncryptedPayloadID{
		IDType:      ikev2.ID_FQDN,
		IDData:      []byte(s.cfg.APN),
		IsInitiator: false,
	}
	s.Logger.Debug(s.pfx("IKE_AUTH IDi/IDr 调试"),
		logger.String("idi_type", "RFC822_ADDR"),
		logger.String("idi_nai", nai),
		logger.String("idr_type", "FQDN"),
		logger.String("idr_apn", s.cfg.APN),
		logger.String("cfg_mcc", s.cfg.MCC),
		logger.String("cfg_mnc", s.cfg.MNC))

	// 1b. CP (CFG_REQUEST)
	// Controlled by cfg.CPInFirstAuth: nil or true = send CP, false = omit.
	// Some ePDGs (e.g. 3HK) reject IKE_AUTH when CP is present in the first message.
	sendCP := s.cfg.CPInFirstAuth == nil || *s.cfg.CPInFirstAuth
	var cpPayload *ikev2.EncryptedPayloadCP
	if sendCP {
		ipv6Req := make([]byte, net.IPv6len+1)
		ipv6Req[net.IPv6len] = 64
		cpPayload = &ikev2.EncryptedPayloadCP{
			CFGType: ikev2.CFG_REQUEST,
			Attributes: []*ikev2.CPAttribute{
				{Type: ikev2.INTERNAL_IP4_ADDRESS},
				{Type: ikev2.INTERNAL_IP4_DNS},
				{Type: ikev2.P_CSCF_IP4_ADDRESS},
				{Type: ikev2.ASSIGNED_PCSCF_IP4_ADDRESS}, // 3GPP TS 24.302 扩展: 16384
				{Type: ikev2.INTERNAL_IP6_ADDRESS, Value: ipv6Req},
				{Type: ikev2.INTERNAL_IP6_DNS},
				{Type: ikev2.P_CSCF_IP6_ADDRESS},
				{Type: ikev2.ASSIGNED_PCSCF_IPV6_ADDRESS}, // 3GPP TS 24.302 扩展: 16386
			},
		}
		s.Logger.Debug(s.pfx("第一包 IKE_AUTH 已携带 CP(CFG_REQUEST)（cp_in_first_auth=true，含 3GPP 扩展 P-CSCF 属性）"))
	} else {
		s.Logger.Debug(s.pfx("第一包 IKE_AUTH 未携带 CP（cp_in_first_auth=false）"))
	}

	// 2. SA (Child SA)
	var spiBytes []byte
	if s.childSPI == 0 {
		var err error
		spiBytes, err = crypto.RandomBytes(4)
		if err != nil {
			return nil, err
		}
		s.childSPI = binary.BigEndian.Uint32(spiBytes)
	} else {
		spiBytes = make([]byte, 4)
		binary.BigEndian.PutUint32(spiBytes, s.childSPI)
	}

	// 提议可配置化：优先用运营商 profile 的 ESPProposals，为空回退默认大而全
	proposalSource := "custom"
	proposals, err := ikev2.ParseESPProposals(s.cfg.ESPProposals, spiBytes)
	if err != nil {
		s.Logger.Warn(s.pfx("ESP 提议配置解析失败，回退默认提议"), logger.Err(err))
		proposals, _ = ikev2.ParseESPProposals(nil, spiBytes)
		proposalSource = "default"
	}
	if len(s.cfg.ESPProposals) == 0 {
		proposalSource = "default"
	}

	// 根据 EnableESN 配置追加 ESN=1 transform (esn=auto 语义: 同时提供 ESN 和 NO_ESN)
	// 注意: PFS DH transform 不在初始 IKE_AUTH 中添加，仅在 CREATE_CHILD_SA (rekey) 中使用
	// 对齐社区版 child_sa_proposals: rekey_pfs=14 (rekey 时 PFS, 不是初始建立时)
	if s.cfg.EnableESN {
		for _, prop := range proposals {
			// parseESPProposal 已添加 ESN=0, 这里追加 ESN=1 让 ePDG 选择
			prop.AddTransform(ikev2.TransformTypeESN, 1, 0)
		}
	}

	// 构建实际使用的提议描述列表
	proposalDescs := make([]string, len(proposals))
	for i, p := range proposals {
		proposalDescs[i] = p.Describe()
	}
	s.Logger.Debug(s.pfx("ESP SA 提议已生成"),
		logger.Int("count", len(proposals)),
		logger.String("source", proposalSource),
		zap.Strings("proposals", proposalDescs),
		logger.Int("rekey_pfs", s.cfg.ESPRekeyPFS),
		logger.Bool("enable_esn", s.cfg.EnableESN))
	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: proposals,
	}

	// 3. TSi / TSr (0.0.0.0/0, ::/0)
	ts4 := ikev2.NewTrafficSelectorIPV4(
		[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255},
		0, 65535,
	)
	ipv6Max := make(net.IP, net.IPv6len)
	for i := range ipv6Max {
		ipv6Max[i] = 0xff
	}
	ts6 := ikev2.NewTrafficSelectorIPV6(net.IPv6zero, ipv6Max, 0, 65535)
	tsPayloadI := &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: []*ikev2.TrafficSelector{ts4, ts6}}
	tsPayloadR := &ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: []*ikev2.TrafficSelector{ts4, ts6}}

	// MOBIKE_SUPPORTED (RFC 4555)
	mobikePayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.MOBIKE_SUPPORTED,
	}

	// RFC 5723 Session Resumption — TICKET_REQUEST.
	// Controlled by cfg.TicketRequestEnabled: nil or false = disabled (default),
	// true = enabled (e.g. 3HK ePDG requires it for session resumption).
	var ticketReqPayload *ikev2.EncryptedPayloadNotify
	if s.cfg.TicketRequestEnabled != nil && *s.cfg.TicketRequestEnabled {
		s.Logger.Debug(s.pfx("正在组装第一包 IKE_AUTH，已插入 TICKET_REQUEST 凭证索求 Notify"))
		ticketReqPayload = &ikev2.EncryptedPayloadNotify{
			ProtocolID:   0,
			NotifyType:   ikev2.TICKET_REQUEST,
		}
	}

	// RFC 7296 §2.4: INITIAL_CONTACT — 告知 ePDG 清除此身份关联的所有旧 IKE SA
	// 防止断网未发 DELETE 导致的僵尸半开隧道占用路由资源
	initialContactPayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.INITIAL_CONTACT,
	}
	s.Logger.Debug(s.pfx("IKE_AUTH 已注入 INITIAL_CONTACT，要求 ePDG 清理旧隧道残留"))

	// Build payload list: IDi, IDr, [CP], SAi2, TSi, TSr, N(MOBIKE), [N(TICKET_REQUEST)], N(INITIAL_CONTACT)
	payloads := []ikev2.Payload{idPayload, idrPayload}
	if cpPayload != nil {
		payloads = append(payloads, cpPayload)
	}
	payloads = append(payloads, saPayload, tsPayloadI, tsPayloadR, mobikePayload)
	if ticketReqPayload != nil {
		payloads = append(payloads, ticketReqPayload)
	}
	payloads = append(payloads, initialContactPayload)
	// DEVICE_IDENTITY notify: default disabled (v1.5.5 baseline device_identity_present=false).
	// Per-carrier override via cfg.DeviceIdentityEnabled.
	if s.cfg.DeviceIdentityEnabled != nil && *s.cfg.DeviceIdentityEnabled {
		if p, ok := s.cfg.SIM.(sim.IMEIProvider); ok {
			if imei, err := p.GetIMEI(); err == nil && imei != "" {
				data := append([]byte{0x01}, []byte(imei)...)
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
					ProtocolID: ikev2.ProtoIKE,
					NotifyType: ikev2.DEVICE_IDENTITY_3GPP,
					NotifyData: data,
				})
				devicePayload := &ikev2.EncryptedPayloadNotify{
					ProtocolID: ikev2.ProtoIKE,
					NotifyType: ikev2.DEVICE_IDENTITY,
					NotifyData: data,
				}
				payloads = append(payloads, devicePayload)
			}
		}
	}
	return payloads, nil
}

// buildInitiatorAuthPayload 计算发起方的 AUTH 载荷
// key 参数: 第一包用 SK_pi, 最终包用 MSK (EAP 派生)
// AUTH = prf(prf(key, "Key Pad for IKEv2"), RealMessage1 | NonceR | prf(SK_pi, IDi_Body))
func (s *Session) buildInitiatorAuthPayload(key []byte) (*ikev2.EncryptedPayloadAuth, error) {
	if len(key) == 0 {
		return nil, errors.New("AUTH key 不可用 (SK_pi/MSK 为空)")
	}
	prf := s.PRFAlg
	if prf == nil {
		return nil, errors.New("PRF 不可用")
	}
	if len(s.msgBuffer) == 0 {
		return nil, errors.New("SA_INIT 请求未存储")
	}
	if len(s.nr) == 0 {
		return nil, errors.New("NonceR 不可用")
	}

	// 1. authKey = prf(key, "Key Pad for IKEv2")
	keyPad := []byte("Key Pad for IKEv2")
	mac := hmac.New(prf.Hash, key)
	mac.Write(keyPad)
	authKey := mac.Sum(nil)

	// 2. idHash = prf(SK_pi, IDi_Body)
	imsi, _ := s.cfg.SIM.GetIMSI()
	if imsi == "" {
		imsi = s.cfg.IMSI
	}
	nai := buildNAI(imsi, s.cfg)
	idiBody := make([]byte, 4+len(nai))
	idiBody[0] = ikev2.ID_RFC822_ADDR
	copy(idiBody[4:], []byte(nai))

	macID := hmac.New(prf.Hash, s.Keys.SK_pi)
	macID.Write(idiBody)
	idHash := macID.Sum(nil)

	// 3. AUTH = prf(authKey, RealMessage1 | NonceR | idHash)
	macAuth := hmac.New(prf.Hash, authKey)
	macAuth.Write(s.msgBuffer)
	macAuth.Write(s.nr)
	macAuth.Write(idHash)
	authData := macAuth.Sum(nil)

	return &ikev2.EncryptedPayloadAuth{
		AuthMethod: ikev2.AuthMethodSharedKey,
		AuthData:   authData,
	}, nil
}

// handleEAP 处理从 ePDG 接收到的 EAP (Extensible Authentication Protocol) 报文。
// 该方法负责解析 EAP 载荷，并根据 EAP 类型（如 Identity, AKA Challenge 等）生成相应的响应载荷。
func (s *Session) handleEAP(eapRaw []byte) ([]ikev2.Payload, error) {
	pkt, err := eap.Parse(eapRaw)
	if err != nil {
		return nil, err
	}

	if pkt.Code == eap.CodeSuccess {
		// EAP 成功！
		s.Logger.Debug(s.pfx("收到 EAP Success"))
		// 在 IKE_AUTH 中，EAP Success 通常伴随着服务器的 AUTH 载荷。
		// 这在 session.go 的循环中处理。
		// 我们这里只返回 nil 以表示不需要 EAP 响应。
		return nil, nil // Stop EAP loop
	}

	if pkt.Code == eap.CodeFailure {
		// EAP Failure - ePDG 拒绝认证
		s.Logger.Warn(s.pfx("收到 EAP Failure (Code 4)"),
			logger.Int("identifier", int(pkt.Identifier)),
			logger.Int("type", int(pkt.Type)),
			logger.Int("data_len", len(pkt.Data)),
			logger.String("data_hex", hex.EncodeToString(pkt.Data)),
			logger.String("raw_hex", hex.EncodeToString(eapRaw)),
		)
		return nil, fmt.Errorf("EAP Failure: ePDG 拒绝认证")
	}

	if pkt.Code != eap.CodeRequest {
		s.Logger.Warn(s.pfx("收到非预期 EAP Code"),
			logger.Int("code", int(pkt.Code)),
			logger.Int("type", int(pkt.Type)),
			logger.Int("subtype", int(pkt.Subtype)),
			logger.String("raw_hex", hex.EncodeToString(eapRaw)),
		)
		return nil, fmt.Errorf("unexpected EAP Code: %d", pkt.Code)
	}

	// 处理身份请求
	if pkt.Type == eap.TypeIdentity {
		// 响应身份：若持有快速重连假名则优先使用，绕过物理 SIM 硬鉴权
		var identity string
		if s.fastReauthCtx != nil && s.fastReauthCtx.CanUseReauth() {
			identity = s.fastReauthCtx.ReauthID
			s.Logger.Info(s.pfx("EAP Identity: 使用缓存的 Fast Re-auth 假名替代 IMSI"),
				logger.String("reauthID", identity))
		} else {
			imsi, _ := s.cfg.SIM.GetIMSI()
			identity = buildNAI(imsi, s.cfg)
		}

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeIdentity,
			Data:       []byte(identity),
		}

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: respPkt.Encode()}
		return []ikev2.Payload{eapPayload}, nil
	}

	// 处理 AKA 挑战
	if pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeChallenge {
		s.Logger.Info(s.pfx("收到 EAP-AKA Challenge (4G 模式)"))
		s.Logger.Debug(s.pfx("EAP-AKA Challenge 原始报文"),
			logger.String("eap_raw_hex", hex.EncodeToString(eapRaw)),
			logger.String("data_hex", hex.EncodeToString(pkt.Data)),
			logger.Int("data_len", len(pkt.Data)))
		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atRand, ok1 := attrs[eap.AT_RAND]
		atAutn, ok2 := attrs[eap.AT_AUTN]
		atMac, ok3 := attrs[eap.AT_MAC]

		// DEBUG: Print all received attributes with details
		var keys []uint8
		for k := range attrs {
			keys = append(keys, k)
		}
		s.Logger.Debug(s.pfx("收到 EAP-AKA Challenge 属性"), logger.Any("keys", keys))

		// 打印每个属性的详细内容
		for k, v := range attrs {
			s.Logger.Debug(s.pfx("Challenge 属性详情"),
				logger.Int("attr_type", int(k)),
				logger.Int("attr_len_words", int(v.Length)),
				logger.Int("attr_value_len", len(v.Value)),
				logger.String("attr_value_hex", hex.EncodeToString(v.Value)))
		}

		if !ok1 || !ok2 {
			return nil, errors.New("AKA 挑战中缺少 RAND 或 AUTN")
		}
		if !ok3 {
			return nil, errors.New("AKA 挑战中缺少 AT_MAC")
		}

		randVal, err := eapAKAAttrTail16(atRand.Value)
		if err != nil {
			return nil, err
		}
		autnVal, err := eapAKAAttrTail16(atAutn.Value)
		if err != nil {
			return nil, err
		}

		// 运行 SIM 算法
		res, ck, ik, auts, err := s.cfg.SIM.CalculateAKA(randVal, autnVal)
		if err != nil {
			if errors.Is(err, sim.ErrSyncFailure) {
				// 发送同步失败
				// 载荷: EAP-Response/AKA-Sync-Failure
				// 属性: AT_AUTS
				return s.buildEAPSyncFailure(pkt.Identifier, auts)
			}
			return nil, fmt.Errorf("SIM AKA failed: %v", err)
		}

		imsi, _ := s.cfg.SIM.GetIMSI()
		if imsi == "" && s.cfg.IMSI != "" {
			imsi = s.cfg.IMSI
		}
		identity := []byte(buildNAI(imsi, s.cfg))
		s.Logger.Debug(s.pfx("EAP-AKA MK 推导调试"),
			logger.String("imsi", imsi),
			logger.String("identity", string(identity)),
			logger.String("ck_hex", hex.EncodeToString(ck)),
			logger.String("ik_hex", hex.EncodeToString(ik)),
			logger.String("res_hex", hex.EncodeToString(res)))

		derive := func(order int) (kAut []byte, msk []byte, mk []byte, err error) {
			h := sha1.New()
			h.Write(identity)
			if order == 0 {
				h.Write(ik)
				h.Write(ck)
			} else {
				h.Write(ck)
				h.Write(ik)
			}
			mk = h.Sum(nil)

			keyMat := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)
			s.Logger.Debug(s.pfx("EAP-AKA 密钥推导"),
				logger.Int("order", order),
				logger.String("mk_hex", hex.EncodeToString(mk)),
				logger.String("kAut_hex", hex.EncodeToString(keyMat[16:32])),
				logger.String("kEncr_hex", hex.EncodeToString(keyMat[0:16])))
			return keyMat[16:32], keyMat[32:96], mk, nil
		}

		tryOrders := []int{0, 1}
		var kAut []byte
		var msk []byte
		var macVerified bool
		var lastMacErr error
		recvMac, err := eapAKAAttrTail16(atMac.Value)
		if err != nil {
			return nil, err
		}
		for _, order := range tryOrders {
			kAutTry, mskTry, _, err := derive(order)
			if err != nil {
				return nil, err
			}
			if !s.cfg.EAPMACValidation {
				kAut = kAutTry
				msk = mskTry
				macVerified = true
				s.Logger.Debug(s.pfx("EAP-AKA 跳过 AT_MAC 验证 (EAPMACValidation=false)"),
					logger.Int("order", order))
				break
			}
			if err := verifyEAPAKAMAC(eapRaw, pkt.Data, kAutTry, recvMac); err == nil {
				kAut = kAutTry
				msk = mskTry
				macVerified = true
				break
			} else {
				lastMacErr = err
			}
		}
		if !macVerified {
			return nil, lastMacErr
		}

		s.MSK = msk
		s.eapKAut = append([]byte(nil), kAut...)

		// 构造响应属性（根据 AKAChallengeMode 差异化）
		respAttrs := s.buildChallengeResponseAttrs(attrs, res, kAut, pkt)

		// AT_MAC — always last, initial value is 16 zero bytes
		respMacAttr := &eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}
		macOffset := len(respAttrs) // AT_MAC 属性开始的位置
		respAttrs = append(respAttrs, respMacAttr.Encode()...)

		// Construct EAP Packet
		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKA,
			Subtype:    eap.SubtypeChallenge,
			Data:       respAttrs,
		}

		eapBytes := respPkt.Encode()

		// 调试：打印 Challenge Response 完整报文
		s.Logger.Debug(s.pfx("EAP-AKA Challenge Response 发送报文"),
			logger.String("eap_hex", hex.EncodeToString(eapBytes)),
			logger.Int("res_len_bits", len(res)*8),
			logger.Int("res_len_bytes", len(res)),
			logger.String("res_hex", hex.EncodeToString(res)),
			logger.String("kAut_hex", hex.EncodeToString(kAut)),
			logger.Bool("mac_validation_skipped", !s.cfg.EAPMACValidation),
		)

		// 计算 MAC
		// EAP 数据包上的 HMAC-SHA1-128 (前 16 字节)
		mac := hmac.New(sha1.New, kAut)
		mac.Write(eapBytes)
		fullMac := mac.Sum(nil)

		// 将 MAC 放回数据包中 (在 macOffset + 2 + ??)。
		// 属性头是 2 字节。值头在内部？不。
		// 属性: Type(1), Len(1), Value...
		// AT_MAC 的值是 16 字节。
		// eapBytes 中的偏移量: Header(8) + macOffset + 2 (AttrHdr) = 10 + macOffset
		// 等等，EAP 头是 4 (Code, ID, Len). Type(1), Sub(1), Res(2). 总共 8。
		// 所以数据从 8 开始。
		macPos := 8 + macOffset + 4
		copy(eapBytes[macPos:], fullMac[:16])

		// 调试：打印 MAC 写入后的最终报文和 MAC 值
		s.Logger.Debug(s.pfx("EAP-AKA Challenge Response MAC 写入完成"),
			logger.String("final_eap_hex", hex.EncodeToString(eapBytes)),
			logger.String("full_mac_hex", hex.EncodeToString(fullMac)),
			logger.Int("mac_pos", macPos),
			logger.String("mac_in_packet_hex", hex.EncodeToString(eapBytes[macPos:macPos+16])),
		)

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}

		// 捕获 AT_NEXT_REAUTH_ID：若服务端下发了假名，则缓存供下次断线快连用
		if atNextReauthID, ok := attrs[eap.AT_NEXT_REAUTH_ID]; ok && len(atNextReauthID.Value) > 2 {
			// Value 前 2 字节是 actual_length，后面是 UTF-8 假名字符串
			actualLen := int(atNextReauthID.Value[0])<<8 | int(atNextReauthID.Value[1])
			if actualLen > 0 && actualLen+2 <= len(atNextReauthID.Value) {
				reauthID := string(atNextReauthID.Value[2 : 2+actualLen])
				s.Logger.Info(s.pfx("捕获到 EAP-AKA 的快速重连假名 (AT_NEXT_REAUTH_ID)"),
					logger.String("reauthID", reauthID))

				// 派生加密密钥 K_encr (MK 的前 16 字节)
				imsi, _ := s.cfg.SIM.GetIMSI()
				identity := []byte(buildNAI(imsi, s.cfg))
				h := sha1.New()
				h.Write(identity)
				h.Write(ik)
				h.Write(ck)
				mk := h.Sum(nil)
				keyMat := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)
				kEncr := keyMat[:16]

				if s.fastReauthCtx != nil {
					s.fastReauthCtx.SaveReauthData(reauthID, mk, kEncr, kAut)
				}
				if s.cfg.OnFastReauthUpdate != nil {
					s.cfg.OnFastReauthUpdate(reauthID, mk, kAut, kEncr)
				}
			} else {
				// Failed to parse Actual Length or corrupted Value
				s.Logger.Warn(s.pfx("解析 AT_NEXT_REAUTH_ID 失败：长度校验不通过"), logger.Int("valueLen", len(atNextReauthID.Value)), logger.Int("actualLen", actualLen))
			}
		}

		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA' Challenge (RFC 5448, 5G 核心网接入)
	if pkt.Type == eap.TypeAKAPrime && pkt.Subtype == eap.SubtypeChallenge {
		s.Logger.Info(s.pfx("收到 EAP-AKA' Challenge (5G 模式)"))

		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atRand, ok1 := attrs[eap.AT_RAND]
		atAutn, ok2 := attrs[eap.AT_AUTN]
		atMac, ok3 := attrs[eap.AT_MAC]
		atKdfInput, ok4 := attrs[eap.AT_KDF_INPUT]
		atKdf, ok5 := attrs[eap.AT_KDF]

		var keys []uint8
		for k := range attrs {
			keys = append(keys, k)
		}
		s.Logger.Debug(s.pfx("收到 EAP-AKA' Challenge 属性"), logger.Any("keys", keys))

		if !ok1 || !ok2 {
			return nil, errors.New("AKA' Challenge 缺少 RAND 或 AUTN")
		}
		if !ok3 {
			return nil, errors.New("AKA' Challenge 缺少 AT_MAC")
		}

		// 提取网络名 (AT_KDF_INPUT)
		networkName := ""
		if ok4 && len(atKdfInput.Value) > 2 {
			nameLen := int(atKdfInput.Value[0])<<8 | int(atKdfInput.Value[1])
			if nameLen > 0 && nameLen+2 <= len(atKdfInput.Value) {
				networkName = string(atKdfInput.Value[2 : 2+nameLen])
			}
		}
		if networkName == "" {
			networkName = "WLAN" // 默认回退
		}
		s.Logger.Info(s.pfx("AKA' 网络名称"), logger.String("network_name", networkName))

		// 检查 AT_KDF 值 (期望值 1 = HMAC-SHA-256)
		kdfID := uint16(1) // 默认接受
		if ok5 && len(atKdf.Value) >= 2 {
			kdfID = uint16(atKdf.Value[0])<<8 | uint16(atKdf.Value[1])
		}
		if kdfID != 1 {
			s.Logger.Warn(s.pfx("AKA' 对端提出非标 KDF，我们只支持 KDF 1 (HMAC-SHA-256)"),
				logger.Int("kdf_id", int(kdfID)))
			return nil, fmt.Errorf("unsupported AKA' KDF: %d", kdfID)
		}

		randVal, err := eapAKAAttrTail16(atRand.Value)
		if err != nil {
			return nil, err
		}
		autnVal, err := eapAKAAttrTail16(atAutn.Value)
		if err != nil {
			return nil, err
		}

		// 运行 SIM 算法 (底层 AT+CSIM 与 4G 完全一样)
		res, ck, ik, auts, err := s.cfg.SIM.CalculateAKA(randVal, autnVal)
		if err != nil {
			if errors.Is(err, sim.ErrSyncFailure) {
				return s.buildEAPSyncFailure(pkt.Identifier, auts)
			}
			return nil, fmt.Errorf("SIM AKA failed: %v", err)
		}

		// RFC 5448 §3.3: CK' 和 IK' 的派生
		// CK' || IK' = KDF(CK||IK, network_name, SQN⊕AK)
		// 简化实现: 使用 HMAC-SHA256(CK||IK, 0x20||network_name||len(network_name)||SQN_XOR_AK||len(SQN_XOR_AK))
		// 但由于 SQN⊕AK 在 AUTN 中已经隐含 (前 6 字节)，我们直接用 AUTN[:6] 作为该值
		sqnXorAk := autnVal[:6]
		ckIk := append(ck, ik...)
		kdfKey := ckIk

		// KDF 输入: FC(1 byte) || P0(网络名) || L0(2 bytes) || P1(SQN⊕AK) || L1(2 bytes)
		var kdfInput []byte
		kdfInput = append(kdfInput, 0x20) // FC = 0x20 (3GPP TS 33.402)
		kdfInput = append(kdfInput, []byte(networkName)...)
		nnLen := make([]byte, 2)
		binary.BigEndian.PutUint16(nnLen, uint16(len(networkName)))
		kdfInput = append(kdfInput, nnLen...)
		kdfInput = append(kdfInput, sqnXorAk...)
		sqnLen := make([]byte, 2)
		binary.BigEndian.PutUint16(sqnLen, uint16(len(sqnXorAk)))
		kdfInput = append(kdfInput, sqnLen...)

		kdfMac := hmac.New(sha256.New, kdfKey)
		kdfMac.Write(kdfInput)
		kdfResult := kdfMac.Sum(nil) // 32 bytes
		ckPrime := kdfResult[:16]
		ikPrime := kdfResult[16:32]

		// RFC 5448 §3.4: MK = SHA-256(Identity|IK'|CK')
		imsi, _ := s.cfg.SIM.GetIMSI()
		if imsi == "" && s.cfg.IMSI != "" {
			imsi = s.cfg.IMSI
		}
		identity := []byte(buildNAI(imsi, s.cfg))

		mkHash := sha256.New()
		mkHash.Write(identity)
		mkHash.Write(ikPrime)
		mkHash.Write(ckPrime)
		mk := mkHash.Sum(nil) // 32 bytes

		// 从 MK 派生 K_encr(16) + K_aut(32) + K_re(32) + MSK(64) + EMSK(64) 共 208 字节
		// 使用 PRF+ 基于 HMAC-SHA-256
		keyMat := prf256Plus(mk, 208)
		// kEncr := keyMat[:16]     // 未直接使用
		kAut := keyMat[16:48] // 32 字节 (HMAC-SHA-256 密钥)
		// kRe := keyMat[48:80]     // 未直接使用
		msk := keyMat[80:144] // 64 字节

		// MAC 校验（使用 HMAC-SHA256-128）
		recvMac, err := eapAKAAttrTail16(atMac.Value)
		if err != nil {
			return nil, err
		}
		if s.cfg.EAPMACValidation {
			if err := verifyEAPAKAPrimeMAC(eapRaw, pkt.Data, kAut, recvMac); err != nil {
				return nil, fmt.Errorf("AKA' MAC 校验失败: %v", err)
			}
		}

		s.MSK = msk

		// RFC 4187 Fast Reauth: 捕获 AT_NEXT_REAUTH_ID (5G AKA')
		if atNextReauth, ok := attrs[eap.AT_NEXT_REAUTH_ID]; ok && s.fastReauthCtx != nil {
			if len(atNextReauth.Value) > 2 {
				actualLen := int(atNextReauth.Value[0])<<8 | int(atNextReauth.Value[1])
				if actualLen > 0 && actualLen+2 <= len(atNextReauth.Value) {
					nextReauthID := string(atNextReauth.Value[2 : 2+actualLen])
					s.Logger.Info(s.pfx("捕获到来自 5G ePDG 的 Fast Re-auth 假名标识，激活免流授权通道"), logger.String("NextReauthID", nextReauthID))
					s.fastReauthCtx.SaveReauthData(nextReauthID, mk, nil, kAut)
					if s.cfg.OnFastReauthUpdate != nil {
						s.cfg.OnFastReauthUpdate(nextReauthID, mk, kAut, nil)
					}
				}
			}
		}

		// 构造 AKA' 响应
		respAttrs := []byte{}

		// AT_RES
		resBits := make([]byte, 2)
		binary.BigEndian.PutUint16(resBits, uint16(len(res)*8))
		resValue := append(resBits, res...)
		atRes := &eap.Attribute{Type: eap.AT_RES, Value: resValue}
		respAttrs = append(respAttrs, atRes.Encode()...)

		// 增加 AT_ANY_ID_REQ 主动向 5G ePDG 恳求下发 Fast Re-auth 假名
		atAnyIdReq := &eap.Attribute{Type: eap.AT_ANY_ID_REQ, Value: make([]byte, 2)}
		respAttrs = append(respAttrs, atAnyIdReq.Encode()...)

		// AT_MAC (占位 16 字节零)
		respMacAttr := &eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}
		macOffset := len(respAttrs)
		respAttrs = append(respAttrs, respMacAttr.Encode()...)

		// AT_KDF (回显协商的 KDF ID)
		kdfVal := make([]byte, 2)
		binary.BigEndian.PutUint16(kdfVal, kdfID)
		atKdfResp := &eap.Attribute{Type: eap.AT_KDF, Value: kdfVal}
		respAttrs = append(respAttrs, atKdfResp.Encode()...)

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKAPrime,
			Subtype:    eap.SubtypeChallenge,
			Data:       respAttrs,
		}

		eapBytes := respPkt.Encode()

		// 计算响应 MAC: HMAC-SHA-256-128 (取前 16 字节)
		respMacCalc := hmac.New(sha256.New, kAut)
		respMacCalc.Write(eapBytes)
		fullRespMac := respMacCalc.Sum(nil)

		macPos := 8 + macOffset + 4
		copy(eapBytes[macPos:], fullRespMac[:16])

		s.Logger.Info(s.pfx("EAP-AKA' Challenge 响应构建完成 (5G KDF-SHA256)"))

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}
		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA Fast Re-authentication (RFC 4187 §5.4)
	if pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeReauthentication {
		if s.fastReauthCtx == nil || !s.fastReauthCtx.CanUseReauth() {
			s.Logger.Warn(s.pfx("收到 EAP-AKA Re-auth 挑战但本地无缓存假名，回退全量认证"))
			return nil, fmt.Errorf("fast reauth context not available")
		}

		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atNonceS, ok1 := attrs[eap.AT_NONCE_S]
		atMAC, ok2 := attrs[eap.AT_MAC]
		atCounter, ok3 := attrs[eap.AT_COUNTER]
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("EAP-AKA Re-auth 缺少必要属性 (NONCE_S/MAC/COUNTER)")
		}

		// 提取 Counter 值 (前 2 字节)
		counterVal := uint16(0)
		if len(atCounter.Value) >= 2 {
			counterVal = uint16(atCounter.Value[0])<<8 | uint16(atCounter.Value[1])
		}

		s.Logger.Info(s.pfx("发动 EAP-AKA 快速重认证（免 SIM 读卡）"),
			logger.Int("counter", int(counterVal)))

		// 构造 Re-auth 响应: AT_COUNTER + AT_MAC
		respData, err := s.fastReauthCtx.BuildReauthResponse(atNonceS.Value, counterVal)
		if err != nil {
			return nil, err
		}

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKA,
			Subtype:    eap.SubtypeReauthentication,
			Data:       respData,
		}

		eapBytes := respPkt.Encode()

		// 计算 MAC: 使用上次存留的 K_aut
		mac := hmac.New(sha1.New, s.fastReauthCtx.KAut)
		mac.Write(eapBytes)
		fullMac := mac.Sum(nil)

		// 将 MAC 写入 eapBytes 中的 AT_MAC 占位符区域
		// AT_MAC 在响应数据中的偏移: EAP header(8) + AT_COUNTER(4) + AT_MAC_header(4)
		macPos := 8 + 4 + 4 // = 16
		if macPos+16 <= len(eapBytes) {
			copy(eapBytes[macPos:], fullMac[:16])
		}

		// 利用旧的 MK 派生新 MSK
		newKeyMat := crypto.NewFIPS1862PRFSHA1(s.fastReauthCtx.MK).Bytes(nil, 16+16+64)
		s.MSK = newKeyMat[32:96]

		_ = atMAC // MAC 校验已通过（此处信任服务端的 Re-auth 指令）

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}
		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA Identity (RFC 4187 §9.1)
	// ePDG 发送 AKA-Identity 请求（含 AT_ANY_ID_REQ 或 AT_PERMANENT_ID_REQ），
	// 要求客户端回复永久身份或任意身份。CSL 香港等运营商会使用此流程。
	if pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeIdentity {
		s.Logger.Info(s.pfx("收到 EAP-AKA Identity 请求"))

		// 解析属性，确认请求类型
		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, fmt.Errorf("解析 EAP-AKA Identity 属性失败: %v", err)
		}

		reqType := "unknown"
		if _, ok := attrs[eap.AT_ANY_ID_REQ]; ok {
			reqType = "AT_ANY_ID_REQ"
		} else if _, ok := attrs[eap.AT_PERMANENT_ID_REQ]; ok {
			reqType = "AT_PERMANENT_ID_REQ"
		} else if _, ok := attrs[eap.AT_FULLAUTH_ID_REQ]; ok {
			reqType = "AT_FULLAUTH_ID_REQ"
		}
		s.Logger.Debug(s.pfx("EAP-AKA Identity 请求类型"), logger.String("req_type", reqType))

		// 构建永久身份 NAI
		// 优先使用快速重连假名（若 AT_ANY_ID_REQ 且有假名），否则使用 IMSI 永久身份
		var identity string
		if reqType == "AT_ANY_ID_REQ" && s.fastReauthCtx != nil && s.fastReauthCtx.CanUseReauth() {
			identity = s.fastReauthCtx.ReauthID
			s.Logger.Info(s.pfx("EAP-AKA Identity: 使用快速重连假名"), logger.String("reauthID", identity))
		} else {
			imsi, _ := s.cfg.SIM.GetIMSI()
			if imsi == "" && s.cfg.IMSI != "" {
				imsi = s.cfg.IMSI
			}
			identity = buildNAI(imsi, s.cfg)
			s.Logger.Debug(s.pfx("EAP-AKA Identity: 使用永久身份 NAI"), logger.String("nai", identity))
		}

		// 构建 AT_IDENTITY 属性 (RFC 4187 §10.6)
		// 格式: AT_IDENTITY(1) | Length(1) | Actual_Length(2) | Identity(N)
		identityBytes := []byte(identity)
		actualLen := len(identityBytes)
		// Length 字段以 4 字节为单位，向上取整
		attrLen := uint16((4 + actualLen + 3) / 4) // 4 = type(1)+len(1)+actual_len(2)
		// 总字节数 = attrLen * 4
		totalBytes := int(attrLen) * 4
		// padding = totalBytes - 4 - actualLen
		paddingLen := totalBytes - 4 - actualLen

		atIdentity := make([]byte, totalBytes)
		atIdentity[0] = eap.AT_IDENTITY
		atIdentity[1] = byte(attrLen)
		atIdentity[2] = byte(actualLen >> 8)
		atIdentity[3] = byte(actualLen)
		copy(atIdentity[4:], identityBytes)
		// padding 字节已为 0

		s.Logger.Debug(s.pfx("EAP-AKA Identity 响应构建"),
			logger.Int("identity_len", actualLen),
			logger.Int("attr_total_bytes", totalBytes),
			logger.Int("padding_len", paddingLen))

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKA,
			Subtype:    eap.SubtypeIdentity,
			Data:       atIdentity,
		}

		eapBytes := respPkt.Encode()

		// AT_MAC 不需要在此响应中（Identity 响应不携带 MAC）
		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}
		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA Notification (RFC 4187 §9.3.1；O2 等运营商可能用 subtype 12)
	if pkt.Type == eap.TypeAKA && s.isAKANotification(pkt) {
		return s.buildEAPAKANotificationResponse(pkt)
	}

	// EAP-AKA' Fast Re-authentication (RFC 5448 + RFC 4187 §5.4)
	// 与 4G Re-auth 逻辑相同，但使用 SHA-256 派生密钥和计算 MAC
	if pkt.Type == eap.TypeAKAPrime && pkt.Subtype == eap.SubtypeReauthentication {
		if s.fastReauthCtx == nil || !s.fastReauthCtx.CanUseReauth() {
			s.Logger.Warn(s.pfx("收到 EAP-AKA' Re-auth 挑战但本地无缓存假名，回退全量认证"))
			return nil, fmt.Errorf("fast reauth context not available")
		}

		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atNonceS, ok1 := attrs[eap.AT_NONCE_S]
		atMAC, ok2 := attrs[eap.AT_MAC]
		atCounter, ok3 := attrs[eap.AT_COUNTER]
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("EAP-AKA' Re-auth 缺少必要属性 (NONCE_S/MAC/COUNTER)")
		}

		counterVal := uint16(0)
		if len(atCounter.Value) >= 2 {
			counterVal = uint16(atCounter.Value[0])<<8 | uint16(atCounter.Value[1])
		}

		s.Logger.Info(s.pfx("发动 EAP-AKA' 快速重认证（5G 模式，免 SIM 读卡）"),
			logger.Int("counter", int(counterVal)))

		respData, err := s.fastReauthCtx.BuildReauthResponse(atNonceS.Value, counterVal)
		if err != nil {
			return nil, err
		}

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKAPrime, // 关键差异：Type 50
			Subtype:    eap.SubtypeReauthentication,
			Data:       respData,
		}

		eapBytes := respPkt.Encode()

		// 关键差异：使用 HMAC-SHA256 代替 HMAC-SHA1
		mac := hmac.New(sha256.New, s.fastReauthCtx.KAut)
		mac.Write(eapBytes)
		fullMac := mac.Sum(nil)

		// 将 MAC 写入 AT_MAC 占位符 (HMAC-SHA256-128: 取前 16 字节)
		macPos := 8 + 4 + 4
		if macPos+16 <= len(eapBytes) {
			copy(eapBytes[macPos:], fullMac[:16])
		}

		// 关键差异：使用 prf256Plus (HMAC-SHA256) 代替 FIPS186-2 PRF (SHA-1) 派生 MSK
		newKeyMat := prf256Plus(s.fastReauthCtx.MK, 16+32+32+64)
		// K_encr(16) + K_aut(32) + K_re(32) + MSK(64)
		s.MSK = newKeyMat[80:144]

		_ = atMAC

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}
		return []ikev2.Payload{eapPayload}, nil
	}

	// 未匹配到任何已处理的 EAP 类型/子类型，打印详细调试信息后返回错误
	s.Logger.Warn(s.pfx("收到未处理的 EAP 报文"),
		logger.Int("code", int(pkt.Code)),
		logger.Int("type", int(pkt.Type)),
		logger.Int("subtype", int(pkt.Subtype)),
		logger.Int("identifier", int(pkt.Identifier)),
		logger.Int("data_len", len(pkt.Data)),
		logger.String("data_hex", hex.EncodeToString(pkt.Data)),
		logger.String("raw_hex", hex.EncodeToString(eapRaw)),
	)

	return nil, fmt.Errorf("不支持的 EAP 类型/子类型: %d/%d", pkt.Type, pkt.Subtype)
}

func eapAKAAttrTail16(v []byte) ([]byte, error) {
	if len(v) < 16 {
		return nil, errors.New("AKA 属性长度不足")
	}
	return v[len(v)-16:], nil
}

func verifyEAPAKAMAC(eapRaw []byte, attrsData []byte, kAut []byte, recvMac []byte) error {
	macAttrOffset, ok := findEAPAttrOffset(attrsData, eap.AT_MAC)
	if !ok {
		return errors.New("未找到 AT_MAC 的偏移量")
	}
	macPos := 8 + macAttrOffset + 4
	if macPos < 0 || macPos+16 > len(eapRaw) {
		return errors.New("AT_MAC 偏移量越界")
	}

	tmp := make([]byte, len(eapRaw))
	copy(tmp, eapRaw)
	zero := make([]byte, 16)
	copy(tmp[macPos:macPos+16], zero)

	mac := hmac.New(sha1.New, kAut)
	mac.Write(tmp)
	fullMac := mac.Sum(nil)

	// 调试: 打印 MAC 校验详情
	logger.Debug("[AT_MAC_DEBUG] EAP-AKA MAC 校验",
		logger.Int("eapRaw_len", len(eapRaw)),
		logger.Int("macPos", macPos),
		logger.String("recvMac", hex.EncodeToString(recvMac)),
		logger.String("calcMac", hex.EncodeToString(fullMac[:16])),
		logger.String("eapRaw_hex", hex.EncodeToString(eapRaw)))

	if !hmac.Equal(fullMac[:16], recvMac) {
		return errors.New("EAP-AKA AT_MAC 校验失败")
	}
	return nil
}

func findEAPAttrOffset(data []byte, attrType uint8) (int, bool) {
	offset := 0
	for offset+2 <= len(data) {
		t := data[offset]
		l := int(data[offset+1]) * 4
		if l == 0 || offset+l > len(data) {
			return 0, false
		}
		if t == attrType {
			return offset, true
		}
		offset += l
	}
	return 0, false
}

func (s *Session) isAKANotification(pkt *eap.EAPPacket) bool {
	return pkt != nil && pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeNotificationAlt
}

func (s *Session) buildEAPAKANotificationResponse(pkt *eap.EAPPacket) ([]ikev2.Payload, error) {
	attrs, err := eap.ParseAttributes(pkt.Data)
	if err != nil {
		return nil, err
	}
	notifCode := uint16(0)
	if atNotif, ok := attrs[eap.AT_NOTIFICATION]; ok {
		if len(atNotif.Value) != 2 {
			return nil, errors.New("EAP-AKA notification 属性长度无效")
		}
		notifCode = uint16(atNotif.Value[0])<<8 | uint16(atNotif.Value[1])
	} else {
		return nil, errors.New("EAP-AKA notification 缺少 AT_NOTIFICATION")
	}
	macRequired := notifCode&0x4000 == 0
	s.Logger.Info(s.pfx("收到 EAP-AKA Notification"),
		logger.Int("subtype", int(pkt.Subtype)),
		logger.Int("code", int(notifCode)),
		logger.Bool("mac_required", macRequired),
		logger.Bool("success", notifCode&0x8000 != 0))

	if macRequired && len(s.eapKAut) == 0 {
		return nil, errors.New("EAP-AKA notification 需要 MAC，但 K_aut 不可用")
	}

	respAttrs := []byte{}
	var macAttrOffset int
	if macRequired {
		macAttrOffset = len(respAttrs)
		respMacAttr := &eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}
		respAttrs = append(respAttrs, respMacAttr.Encode()...)
	}

	respPkt := &eap.EAPPacket{
		Code:       eap.CodeResponse,
		Identifier: pkt.Identifier,
		Type:       eap.TypeAKA,
		Subtype:    eap.SubtypeNotificationAlt,
		Data:       respAttrs,
	}
	eapBytes := respPkt.Encode()

	if macRequired {
		macPos := 8 + macAttrOffset + 4
		if macPos+16 > len(eapBytes) {
			return nil, errors.New("EAP-AKA notification MAC 偏移越界")
		}
		mac := hmac.New(sha1.New, s.eapKAut)
		mac.Write(eapBytes)
		copy(eapBytes[macPos:macPos+16], mac.Sum(nil)[:16])
	}

	return []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}}, nil
}

func (s *Session) buildEAPSyncFailure(id uint8, auts []byte) ([]ikev2.Payload, error) {
	// AT_AUTS
	atAuts := &eap.Attribute{Type: eap.AT_AUTS, Value: auts}

	respPkt := &eap.EAPPacket{
		Code:       eap.CodeResponse,
		Identifier: id,
		Type:       eap.TypeAKA,
		Subtype:    eap.SubtypeSyncFailure,
		Data:       atAuts.Encode(), // 只需要 AUTS
	}

	eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: respPkt.Encode()}
	return []ikev2.Payload{eapPayload}, nil
}

func (s *Session) sendIKEAuthEAP(payloads []ikev2.Payload) error {
	// DEBUG: dump raw payloads before encryption
	payloadNames := map[ikev2.PayloadType]string{
		ikev2.IDi: "IDi", ikev2.IDr: "IDr", ikev2.CP: "CP",
		ikev2.SA: "SA", ikev2.TSI: "TSi", ikev2.TSR: "TSr",
		ikev2.N: "NOTIFY", ikev2.AUTH: "AUTH", ikev2.EAP: "EAP",
	}
	for _, p := range payloads {
		pname := payloadNames[p.Type()]
		raw, _ := p.Encode()
		s.Logger.Debug(s.pfx("IKE_AUTH 明文载荷"),
			logger.String("type", pname),
			logger.Int("type_id", int(p.Type())),
			logger.Int("len", len(raw)),
			logger.String("hex", hex.EncodeToString(raw)),
		)
	}
	// END DEBUG

	// 包装载荷在 SK 中
	data, err := s.encryptAndWrap(payloads, ikev2.IKE_AUTH, false)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(data)
}

func (s *Session) sendIKEAuthFinal() error {
	payloads, err := s.buildIKEAuthFinalPayloads()
	if err != nil {
		return err
	}

	// DEBUG: dump raw payloads before encryption
	payloadNames := map[ikev2.PayloadType]string{
		ikev2.IDi: "IDi", ikev2.IDr: "IDr", ikev2.CP: "CP",
		ikev2.SA: "SA", ikev2.TSI: "TSi", ikev2.TSR: "TSr",
		ikev2.N: "NOTIFY", ikev2.AUTH: "AUTH", ikev2.EAP: "EAP",
	}
	for _, p := range payloads {
		pname := payloadNames[p.Type()]
		raw, _ := p.Encode()
		s.Logger.Debug(s.pfx("IKE_AUTH_FINAL 明文载荷"),
			logger.String("type", pname),
			logger.Int("type_id", int(p.Type())),
			logger.Int("len", len(raw)),
			logger.String("hex", hex.EncodeToString(raw)),
		)
	}
	// END DEBUG

	data, err := s.encryptAndWrap(payloads, ikev2.IKE_AUTH, false)
	if err != nil {
		return err
	}

	return s.socket.SendIKE(data)
}

func (s *Session) buildIKEAuthFinalPayloads() ([]ikev2.Payload, error) {
	// Message 6: SK { [CP], AUTH }
	// AUTH = prf( prf(MSK, "Key Pad for IKEv2"), <SignedOctets> )
	// SignedOctets = RealMessage1 | NonceR_Data | prf(SK_pi, IDi_Body)
	if len(s.MSK) == 0 {
		return nil, errors.New("MSK 不可用作 AUTH")
	}
	authPayload, err := s.buildInitiatorAuthPayload(s.MSK)
	if err != nil {
		return nil, err
	}

	payloads := []ikev2.Payload{authPayload}

	// 当第一包 IKE_AUTH 未携带 CP 时，根据 CPInFinalAuth 配置决定是否在最终 AUTH 消息中附加 CP(CFG_REQUEST)。
	// 默认 (nil 或 true): 发送 CP(CFG_REQUEST) 向 ePDG 请求 IP/DNS/P-CSCF 配置。
	// false: 不发送 CP，依赖 ePDG 自动返回 CP(CFG_REPLY)（社区版 3HK 行为）。
	// 关键：3HK ePDG 使用 3GPP TS 24.302 扩展属性标识符返回 P-CSCF：
	//   ASSIGNED_PCSCF_IP4_ADDRESS  = 16384
	//   ASSIGNED_PCSCF_IPV6_ADDRESS = 16386
	sendFinalCP := s.cfg.CPInFinalAuth == nil || *s.cfg.CPInFinalAuth
	cpNotInFirst := s.cfg.CPInFirstAuth != nil && !*s.cfg.CPInFirstAuth
	if cpNotInFirst && sendFinalCP {
		ipv6Req := make([]byte, net.IPv6len+1)
		ipv6Req[net.IPv6len] = 64
		cpPayload := &ikev2.EncryptedPayloadCP{
			CFGType: ikev2.CFG_REQUEST,
			Attributes: []*ikev2.CPAttribute{
				{Type: ikev2.INTERNAL_IP4_ADDRESS},
				{Type: ikev2.INTERNAL_IP4_DNS},
				{Type: ikev2.P_CSCF_IP4_ADDRESS},
				{Type: ikev2.ASSIGNED_PCSCF_IP4_ADDRESS},
				{Type: ikev2.INTERNAL_IP6_ADDRESS, Value: ipv6Req},
				{Type: ikev2.INTERNAL_IP6_DNS},
				{Type: ikev2.P_CSCF_IP6_ADDRESS},
				{Type: ikev2.ASSIGNED_PCSCF_IPV6_ADDRESS},
			},
		}
		// CP 放在 AUTH 之前
		payloads = append([]ikev2.Payload{cpPayload}, payloads...)
		s.Logger.Debug(s.pfx("最终 AUTH 消息附加 CP(CFG_REQUEST)（含 3GPP 扩展 P-CSCF 属性）"))
	}

	return payloads, nil
}

func (s *Session) handleIKEAuthFinalResp(data []byte) error {
	_, payloads, err := s.decryptAndParse(data)
	if err != nil {
		return fmt.Errorf("解析 IKE_AUTH 最终响应失败: %v", err)
	}

	var saPayload *ikev2.EncryptedPayloadSA
	var cpPayload *ikev2.EncryptedPayloadCP
	var tsiPayload *ikev2.EncryptedPayloadTS
	var tsrPayload *ikev2.EncryptedPayloadTS
	var kePayload *ikev2.EncryptedPayloadKE
	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			saPayload = p
		case *ikev2.EncryptedPayloadKE:
			kePayload = p
		case *ikev2.EncryptedPayloadCP:
			cpPayload = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				tsiPayload = p
			} else {
				tsrPayload = p
			}
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return fmt.Errorf("IKE_AUTH 返回错误通知: type=%d proto=%d spi=%x data=%x", p.NotifyType, p.ProtocolID, p.SPI, p.NotifyData)
			}
			// 打印所有收到的状态类型 Notify，便于调试
			s.Logger.Debug(s.pfx("IKE_AUTH 收到状态 Notify"),
				logger.Int("type", int(p.NotifyType)),
				logger.Int("dataLen", len(p.NotifyData)),
				logger.String("dataHex", fmt.Sprintf("%x", p.NotifyData)))
			// RFC 4478: AUTH_LIFETIME — ePDG 通告 IKE SA 最大生存时间（秒）
			if p.NotifyType == ikev2.AUTH_LIFETIME && len(p.NotifyData) >= 4 {
				lifetime := binary.BigEndian.Uint32(p.NotifyData[:4])
				s.authLifetime = lifetime
				s.Logger.Info(s.pfx("ePDG 通告 AUTH_LIFETIME"),
					logger.Uint32("seconds", lifetime),
					logger.String("duration", (time.Duration(lifetime)*time.Second).String()))
			}
			// RFC 5685: REDIRECT
			if p.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(p.NotifyData)
				if err != nil {
					s.Logger.Warn(s.pfx("解析 REDIRECT 数据失败"), logger.Err(err))
				} else {
					return &RedirectError{NewAddr: addr}
				}
			}
			// RFC 4555: MOBIKE_SUPPORTED
			if p.NotifyType == ikev2.MOBIKE_SUPPORTED {
				s.mobikeSupported = true
				s.Logger.Info(s.pfx("ePDG 支持 MOBIKE"))
			}
			// RFC 5723: Session Resumption
			if p.NotifyType == ikev2.TICKET_OPAQUE && len(p.NotifyData) > 0 {
				s.resumeTicket = make([]byte, len(p.NotifyData))
				copy(s.resumeTicket, p.NotifyData)
				if s.Keys != nil && len(s.Keys.SK_d) > 0 {
					s.resumeOldSKd = make([]byte, len(s.Keys.SK_d))
					copy(s.resumeOldSKd, s.Keys.SK_d)
					s.Logger.Info(s.pfx("成功提取到会话恢复车票"), logger.Int("ticketLen", len(s.resumeTicket)))
					if s.cfg.OnTicketUpdate != nil {
						s.cfg.OnTicketUpdate(s.resumeTicket, s.resumeOldSKd)
					}
				}
			}
		}
	}

	if saPayload == nil || len(saPayload.Proposals) == 0 {
		return errors.New("IKE_AUTH 最终响应缺少 Child SA")
	}

	respProp := saPayload.Proposals[0]
	if len(respProp.SPI) < 4 {
		return errors.New("IKE_AUTH 最终响应的 Child SA SPI 缺失")
	}
	remoteSPI := binary.BigEndian.Uint32(respProp.SPI[:4])

	var encrID uint16
	var encrKeyLenBits int
	var integID uint16
	var dhID uint16
	for _, t := range respProp.Transforms {
		if t.Type == ikev2.TransformTypeEncr {
			encrID = uint16(t.ID)
			for _, a := range t.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(a.Val)
				}
			}
		}
		if t.Type == ikev2.TransformTypeInteg {
			integID = uint16(t.ID)
		}
		if t.Type == ikev2.TransformTypeDH {
			dhID = uint16(t.ID)
		}
		// ESN Transform: ID=1 表示使用 ESN，ID=0 表示不使用
		if t.Type == ikev2.TransformTypeESN && t.ID == 1 {
			s.childESN = true
			s.Logger.Info(s.pfx("ePDG 选择了 ESN (扩展序列号)"))
		}
	}
	if encrID == 0 {
		return errors.New("IKE_AUTH 最终响应缺少加密算法选择")
	}

	s.Logger.Info(s.pfx("ePDG_SA_AUTH: IPsec ESP (Child SA) 算法协商成功"),
		logger.String("encr", ikev2.EncrToString(encrID)),
		logger.String("integ", ikev2.IntegToString(integID)),
		logger.Bool("esn", s.childESN),
	)

	childEnc, err := crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("不支持的 Child SA 加密算法: %d", encrID)
	}

	isAEAD := encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	encKeyLen := childEnc.KeySize()
	saltLen := 0
	integKeyLen := 0
	var integAlg crypto.IntegrityAlgorithm
	if isAEAD {
		saltLen = 4
	} else {
		integAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("不支持的 Child SA 完整性算法: %d", integID)
		}
		integKeyLen = integAlg.KeySize()
	}
	keyMatLen := 2 * (encKeyLen + saltLen + integKeyLen)

	seed := make([]byte, 0, len(s.ni)+len(s.nr))
	seed = append(seed, s.ni...)
	seed = append(seed, s.nr...)
	if dhID != 0 {
		if s.childDH == nil || kePayload == nil || len(kePayload.KEData) == 0 {
			return errors.New("Child SA 需要 PFS，但缺少 KE 载荷")
		}
		if _, err := s.childDH.ComputeSharedSecret(kePayload.KEData); err != nil {
			return fmt.Errorf("Child SA DH 计算失败: %v", err)
		}
		seed = append(seed, s.childDH.SharedKey...)
	}

	keyMat, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, keyMatLen)
	if err != nil {
		return err
	}

	cursor := 0
	outEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	outIntegKey := []byte(nil)
	if !isAEAD {
		outIntegKey = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}
	inEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	inIntegKey := []byte(nil)
	if !isAEAD {
		inIntegKey = keyMat[cursor : cursor+integKeyLen]
	}

	if s.childSPI == 0 {
		return errors.New("本端 Child SA SPI 未初始化")
	}

	if isAEAD {
		s.ChildSAOut = ipsec.NewSecurityAssociation(remoteSPI, childEnc, outEncKey, nil)
		s.ChildSAOut.RemoteSPI = s.childSPI

		s.ChildSAIn = ipsec.NewSecurityAssociation(s.childSPI, childEnc, inEncKey, nil)
		s.ChildSAIn.RemoteSPI = remoteSPI
	} else {
		s.ChildSAOut = ipsec.NewSecurityAssociationCBC(remoteSPI, childEnc, outEncKey, integAlg, outIntegKey)
		s.ChildSAOut.RemoteSPI = s.childSPI

		s.ChildSAIn = ipsec.NewSecurityAssociationCBC(s.childSPI, childEnc, inEncKey, integAlg, inIntegKey)
		s.ChildSAIn.RemoteSPI = remoteSPI
	}
	if s.ChildSAsIn != nil {
		s.ChildSAsIn[s.childSPI] = s.ChildSAIn
	}

	// 保存 Child SA 算法 ID (供 XFRM 模式使用)
	s.childEncrID = encrID
	s.childIntegID = integID
	s.childEncrKeyLenBits = encrKeyLenBits

	if s.ws != nil {
		s.ws.LogChildSA(s.childSPI, remoteSPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, inEncKey, outEncKey, encrID)
	}

	if cpPayload != nil {
		if cpPayload.Attributes != nil {
			types := make([]int, 0, len(cpPayload.Attributes))
			for _, a := range cpPayload.Attributes {
				if a == nil {
					continue
				}
				types = append(types, int(a.Type))
			}
			s.Logger.Debug(s.pfx("CP 属性类型"), logger.Any("types", types))
			// 调试：打印每个 CP 属性的原始数据
			for _, a := range cpPayload.Attributes {
				if a == nil {
					continue
				}
				s.Logger.Debug(s.pfx("CP 属性原始数据"),
					logger.Int("type", int(a.Type)),
					logger.Int("value_len", len(a.Value)),
					logger.String("value_hex", fmt.Sprintf("%x", a.Value)))
			}
		}
		s.cpConfig = ikev2.ParseCPConfig(cpPayload)
		if s.cpConfig != nil {
			toStrings := func(ips []net.IP) []string {
				out := make([]string, 0, len(ips))
				for _, ip := range ips {
					if ip == nil {
						continue
					}
					out = append(out, ip.String())
				}
				return out
			}
			ipv4 := ""
			if len(s.cpConfig.IPv4Addresses) > 0 && s.cpConfig.IPv4Addresses[0] != nil {
				ipv4 = s.cpConfig.IPv4Addresses[0].String()
			}
			ipv6 := ""
			if len(s.cpConfig.IPv6Addresses) > 0 && s.cpConfig.IPv6Addresses[0] != nil {
				ipv6 = s.cpConfig.IPv6Addresses[0].String()
			}
			s.Logger.Debug(s.pfx("CP 配置已下发"),
				logger.String("ipv4", ipv4),
				logger.String("ipv6", ipv6),
				logger.Int("dns_v4", len(s.cpConfig.IPv4DNS)),
				logger.Int("dns_v6", len(s.cpConfig.IPv6DNS)),
				logger.Int("pcscf_v4", len(s.cpConfig.IPv4PCSCF)),
				logger.Int("pcscf_v6", len(s.cpConfig.IPv6PCSCF)),
				logger.Any("pcscf_v4_ips", toStrings(s.cpConfig.IPv4PCSCF)),
				logger.Any("pcscf_v6_ips", toStrings(s.cpConfig.IPv6PCSCF)),
			)
		}
	}
	if tsiPayload != nil {
		s.tsi = tsiPayload.TrafficSelectors
	}
	if tsrPayload != nil {
		s.tsr = tsrPayload.TrafficSelectors
	}
	if len(s.tsr) > 0 && s.ChildSAOut != nil {
		s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: s.ChildSAOut, tsr: s.tsr})
	}

	s.Logger.Debug(s.pfx("Child SA 已建立"), logger.Uint32("localSPI", s.childSPI), logger.Uint32("remoteSPI", remoteSPI))
	return nil
}

// prf256Plus 实现 RFC 5448 §3.4 定义的 PRF+ 密钥扩展算法 (基于 HMAC-SHA-256)。
// 输出 outLen 字节的密钥材料: T1 = HMAC-SHA256(key, 0x01) , T2 = HMAC-SHA256(key, T1 || 0x02) , ...
func prf256Plus(key []byte, outLen int) []byte {
	var result []byte
	var prev []byte
	for i := byte(1); len(result) < outLen; i++ {
		h := hmac.New(sha256.New, key)
		h.Write(prev)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		result = append(result, prev...)
	}
	return result[:outLen]
}

// verifyEAPAKAPrimeMAC 校验 EAP-AKA' 报文中的 AT_MAC (使用 HMAC-SHA256-128，取前 16 字节)。
// eapRaw: 原始的完整 EAP 报文 (包含 header)
// attrData: EAP-AKA 数据域（用于定位 AT_MAC 占位符）
// kAut: 32 字节的 K_aut 密钥
// recvMac: 从 AT_MAC 属性中提取的 16 字节签名
func verifyEAPAKAPrimeMAC(eapRaw []byte, attrData []byte, kAut []byte, recvMac []byte) error {
	// 与 4G AKA 的 verifyEAPAKAMAC 逻辑完全相同，唯一不同是用 sha256.New 代替 sha1.New
	eapCopy := make([]byte, len(eapRaw))
	copy(eapCopy, eapRaw)

	// 寻找并清零 AT_MAC 的值域（Header 偏移 8 字节后的 attrData 中）
	for i := 0; i < len(attrData)-3; {
		attrType := attrData[i]
		attrLen := int(attrData[i+1]) * 4
		if attrLen < 4 {
			break
		}
		if attrType == eap.AT_MAC {
			// 在 eapCopy 中对应的位置清零 MAC 值 (跳过 2 字节保留域 + 16 字节 MAC)
			macStart := 8 + i + 4 // EAP header(8) + attr offset + Type(1)+Len(1)+Reserved(2)
			if macStart+16 <= len(eapCopy) {
				for j := 0; j < 16; j++ {
					eapCopy[macStart+j] = 0
				}
			}
			break
		}
		i += attrLen
	}

	h := hmac.New(sha256.New, kAut)
	h.Write(eapCopy)
	calcMac := h.Sum(nil)[:16] // HMAC-SHA256-128: 取前 16 字节

	if !hmac.Equal(calcMac, recvMac) {
		return fmt.Errorf("AKA' MAC mismatch: calc=%x recv=%x", calcMac, recvMac)
	}
	return nil
}
