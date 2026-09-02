package swu

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"encoding/hex"
	"errors"
	"fmt"

	"github.com/voorz/swu-go/pkg/crypto"
	"github.com/voorz/swu-go/pkg/ikev2"
	"github.com/voorz/swu-go/pkg/logger"
)

// ErrInvalidKEPayload 表示 ePDG 要求使用不同的 DH 组 (RFC 7296 §2.7)
// 发起方应使用 NotifyData 中指定的 DH 组重新生成 KE 并重发 SA_INIT
var ErrInvalidKEPayload = errors.New("ePDG 要求使用不同的 DH 组，需要重发 IKE_SA_INIT")

func detectOutboundIPv4(remoteIP net.IP, remotePort uint16) (net.IP, error) {
	if remoteIP == nil {
		return nil, errors.New("remote ip is nil")
	}
	r := &net.UDPAddr{IP: remoteIP, Port: int(remotePort)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "udp", r.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if v4 := ua.IP.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, errors.New("cannot detect outbound ip")
}

func (s *Session) sendIKESAInit() error {
	data, err := s.buildIKESAInitPacket()
	if err != nil {
		return err
	}
	return s.socket.SendIKE(data)
}

func (s *Session) buildIKESAInitPacket() ([]byte, error) {
	if len(s.ni) == 0 {
		s.ni = make([]byte, 16) // 对齐社区版: Nonce 16 字节
		rand.Read(s.ni)
	}

	// INVALID_KE_PAYLOAD 重试：如果 ePDG 要求使用特定 DH 组，则使用该组
	dhGroup := uint16(14) // 默认 MODP 2048
	if s.keRetryGroup > 0 {
		dhGroup = s.keRetryGroup
		s.Logger.Info(s.pfx("使用 ePDG 指定的 DH 组重新生成 KE"), logger.Uint32("dh_group", uint32(dhGroup)))
	}
	if s.DH == nil || s.DH.Group != dhGroup {
		var err error
		s.DH, err = crypto.NewDiffieHellman(dhGroup)
		if err != nil {
			return nil, err
		}
		if err := s.DH.GenerateKey(); err != nil {
			return nil, err
		}
	}

	// 使用高兼容性的工厂方法生成 Proposal
	proposals := ikev2.CreateMultiProposalIKE(nil)

	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: proposals,
	}

	// [debug] 验证 SA body 大小
	if saBody, err := saPayload.Encode(); err == nil {
		s.Logger.Debug(s.pfx("SA body 编码验证"),
			logger.Int("proposals", len(proposals)),
			logger.Int("body_len", len(saBody)))
	}

	kePayload := &ikev2.EncryptedPayloadKE{
		DHGroup: ikev2.AlgorithmType(dhGroup),
		KEData:  s.DH.PublicKeyBytes(),
	}

	noncePayload := &ikev2.EncryptedPayloadNonce{
		NonceData: s.ni,
	}

	localPort := s.cfg.LocalPort
	if localPort == 0 {
		if lp, ok := s.socket.(interface{ LocalPort() uint16 }); ok {
			localPort = lp.LocalPort()
		}
	}
	remoteIP := net.ParseIP(s.cfg.EpDGAddr).To4()
	remotePort := s.cfg.EpDGPort
	if remotePort == 0 {
		remotePort = 500
	}

	if ep, ok := s.socket.(interface {
		LocalIP() net.IP
		RemoteIP() net.IP
		RemotePort() int
	}); ok {
		if rip := ep.RemoteIP(); rip != nil {
			if v4 := rip.To4(); v4 != nil {
				remoteIP = v4
			}
		}
		if rp := ep.RemotePort(); rp != 0 {
			remotePort = uint16(rp)
		}
	}

	localIP := net.ParseIP(s.cfg.LocalAddr).To4()
	if ep, ok := s.socket.(interface{ LocalIP() net.IP }); ok {
		if lip := ep.LocalIP(); lip != nil {
			if v4 := lip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
				localIP = v4
			}
		}
	}
	if localIP == nil || localIP.Equal(net.IPv4zero) {
		if remoteIP != nil {
			if out, err := detectOutboundIPv4(remoteIP, remotePort); err == nil && out != nil {
				localIP = out
			}
		}
	}

	srcHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, localIP, localPort)
	natSrcPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_SOURCE_IP, srcHash)

	dstHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, remoteIP, remotePort)
	natDstPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_DESTINATION_IP, dstHash)

	// IKE Fragmentation (RFC 7383)
	// IKE_SA_INIT 必须携带此通知
	fragNotify := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.IKEV2_FRAGMENTATION_SUPPORTED,
	}

	// 顺序: SA, KE, Nonce, [COOKIE], NAT_SRC, NAT_DST, FRAG
	// 对齐社区版: NAT_SRC → NAT_DST → FRAG 在最后

	payloads := []ikev2.Payload{saPayload, kePayload, noncePayload}
	if s.sendCookie && len(s.cookie) > 0 {
		payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
			ProtocolID:   0,
			NotifyType:   ikev2.COOKIE,
			NotifyData:   s.cookie,
			OverrideType: ikev2.SA, // 社区版兼容: COOKIE payload 用 SA 类型
		})
	}
	payloads = append(payloads, natSrcPayload, natDstPayload, fragNotify)

	packet := ikev2.NewIKEPacket()
	packet.Header.SPIi = s.SPIi
	packet.Header.Version = 0x20
	packet.Header.ExchangeType = ikev2.IKE_SA_INIT
	packet.Header.Flags = ikev2.FlagInitiator
	packet.Header.MessageID = 0
	packet.Payloads = payloads

	data, err := packet.Encode()
	if err != nil {
		return nil, err
	}

	// [debug] 打印发送的 SA_INIT 请求包 hex（用于对比社区版）
	reqHex := hex.EncodeToString(data)
	if len(reqHex) > 2048 {
		reqHex = reqHex[:2048] + "..."
	}
	s.Logger.Debug(s.pfx("发送 IKE_SA_INIT 请求"),
		logger.Int("len", len(data)),
		logger.Bool("has_cookie", s.sendCookie),
		logger.String("hex", reqHex))

	s.msgBuffer = data
	return data, nil
}

func (s *Session) handleIKESAInitResp(data []byte) error {
	// [debug] 打印收到的原始 IKE 回包（对标社区版 ike_control.go:44）
	rawHex := hex.EncodeToString(data)
	if len(rawHex) > 256 {
		rawHex = rawHex[:256] + "..."
	}
	s.Logger.Debug(s.pfx("收到 IKE 原始回包"),
		logger.Int("len", len(data)),
		logger.String("raw_hex", rawHex))

	packet, err := ikev2.DecodePacket(data)
	if err != nil {
		s.Logger.Warn(s.pfx("SA_INIT 响应解码失败"),
			logger.Err(err),
			logger.Int("len", len(data)),
			logger.String("raw_hex_head", rawHex))
		return fmt.Errorf("解码 SA_INIT 响应失败: %v", err)
	}

	// 检查头部
	if packet.Header.ExchangeType != ikev2.IKE_SA_INIT {
		return fmt.Errorf("意外的交换类型: %d", packet.Header.ExchangeType)
	}
	s.SPIr = packet.Header.SPIr

	// 提取载荷
	var saPayload *ikev2.EncryptedPayloadSA
	var kePayload *ikev2.EncryptedPayloadKE
	var noncePayload *ikev2.EncryptedPayloadNonce
	var natSrc []byte
	var natDst []byte

	// [debug] 遍历载荷时记录每个载荷的类型
	var payloadTypes []string
	for _, p := range packet.Payloads {
		payloadTypes = append(payloadTypes, fmt.Sprintf("%d", int(p.Type())))
		switch v := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			saPayload = v
		case *ikev2.EncryptedPayloadKE:
			kePayload = v
		case *ikev2.EncryptedPayloadNonce:
			noncePayload = v
		case *ikev2.EncryptedPayloadNotify:
			// [debug] 打印每个 Notify 的类型和数据长度（对标社区版 state_init.go:386）
			s.Logger.Debug(s.pfx("SA_INIT 收到状态类 Notify"),
				logger.Uint32("type", uint32(v.NotifyType)),
				logger.Int("data_len", len(v.NotifyData)))
			if v.NotifyType == ikev2.COOKIE {
				if err := s.handleCookie(v.NotifyData); err != nil {
					return err
				}
				return ErrCookieRequired
			}
			if v.NotifyType == ikev2.NAT_DETECTION_SOURCE_IP {
				natSrc = v.NotifyData
			}
			if v.NotifyType == ikev2.NAT_DETECTION_DESTINATION_IP {
				natDst = v.NotifyData
			}
			// IKE Fragmentation (RFC 7383)
			if v.NotifyType == ikev2.IKEV2_FRAGMENTATION_SUPPORTED {
				s.fragmentationSupported = true
				s.Logger.Info(s.pfx("ePDG 支持 IKE Fragmentation"))
			}
			// 检查错误，如 NO_PROPOSAL_CHOSEN
			if v.NotifyType == 14 { // NO_PROPOSAL_CHOSEN
				return errors.New("服务器拒绝了提议 (NO_PROPOSAL_CHOSEN)")
			}
			// RFC 7296 §2.7: INVALID_KE_PAYLOAD
			// ePDG 要求使用不同的 DH 组，NotificationData 是 2 字节 DH Group ID
			if v.NotifyType == ikev2.INVALID_KE_PAYLOAD {
				if len(v.NotifyData) >= 2 {
					reqGroup := binary.BigEndian.Uint16(v.NotifyData[:2])
					s.keRetryGroup = reqGroup
					s.Logger.Info(s.pfx("ePDG 要求使用不同的 DH 组 (INVALID_KE_PAYLOAD)"),
						logger.Uint32("requested_dh_group", uint32(reqGroup)),
						logger.Uint32("current_dh_group", uint32(s.DH.Group)))
					return ErrInvalidKEPayload
				}
				return errors.New("收到 INVALID_KE_PAYLOAD 但缺少 DH 组数据")
			}
			// RFC 5685: REDIRECT
			if v.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(v.NotifyData)
				if err != nil {
					s.Logger.Warn(s.pfx("解析 REDIRECT 数据失败"), logger.Err(err))
				} else {
					return &RedirectError{NewAddr: addr}
				}
			}
		}
	}

	// [debug] 打印载荷清单
	s.Logger.Debug(s.pfx("SA_INIT 响应载荷清单"),
		logger.Int("payload_count", len(packet.Payloads)),
		logger.Any("payload_types", payloadTypes),
		logger.Bool("has_sa", saPayload != nil),
		logger.Bool("has_ke", kePayload != nil),
		logger.Bool("has_nonce", noncePayload != nil))

	if saPayload == nil || kePayload == nil || noncePayload == nil {
		// [debug] 缺少载荷时打印详细诊断信息
		headHex := rawHex
		if len(headHex) > 128 {
			headHex = headHex[:128] + "..."
		}
		s.Logger.Error(s.pfx("SA_INIT 响应中缺少强制性载荷"),
		logger.Bool("has_sa", saPayload != nil),
		logger.Bool("has_ke", kePayload != nil),
		logger.Bool("has_nonce", noncePayload != nil),
		logger.Int("payload_count", len(packet.Payloads)),
		logger.Any("payload_types", payloadTypes),
		logger.String("raw_hex_head", headHex))
		return errors.New("SA_INIT 响应中缺少强制性载荷")
	}

	s.nr = noncePayload.NonceData

	if len(natSrc) > 0 && len(natDst) > 0 {
		localPort := s.cfg.LocalPort
		if localPort == 0 {
			if lp, ok := s.socket.(interface{ LocalPort() uint16 }); ok {
				localPort = lp.LocalPort()
			}
		}
		remoteIP := net.ParseIP(s.cfg.EpDGAddr).To4()
		remotePort := s.cfg.EpDGPort
		if remotePort == 0 {
			remotePort = 500
		}
		if ep, ok := s.socket.(interface {
			LocalIP() net.IP
			RemoteIP() net.IP
			RemotePort() int
		}); ok {
			if rip := ep.RemoteIP(); rip != nil {
				if v4 := rip.To4(); v4 != nil {
					remoteIP = v4
				}
			}
			if rp := ep.RemotePort(); rp != 0 {
				remotePort = uint16(rp)
			}
		}

		localIP := net.ParseIP(s.cfg.LocalAddr).To4()
		if ep, ok := s.socket.(interface{ LocalIP() net.IP }); ok {
			if lip := ep.LocalIP(); lip != nil {
				if v4 := lip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
					localIP = v4
				}
			}
		}
		if localIP == nil || localIP.Equal(net.IPv4zero) {
			if remoteIP != nil {
				if out, err := detectOutboundIPv4(remoteIP, remotePort); err == nil && out != nil {
					localIP = out
				}
			}
		}

		expNatSrc := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, localIP, localPort)
		expNatDst := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, remoteIP, remotePort)

		natDetected := !bytes.Equal(natSrc, expNatSrc) || !bytes.Equal(natDst, expNatDst)
		if natDetected {
			if setter, ok := s.socket.(interface{ SetRemotePort(int) }); ok {
				setter.SetRemotePort(4500)
			}
			natKeepalive := 20 * time.Second
			if s.cfg.NATKeepaliveInterval > 0 {
				natKeepalive = time.Duration(s.cfg.NATKeepaliveInterval) * time.Second
			}
			s.startNATKeepalive(natKeepalive)
			s.Logger.Debug(s.pfx("检测到 NAT，切换到 UDP 4500"))
		}
	}

	// 处理 SA 选择 (简化: 假设服务器接受了我们的提议)
	// 我们应该解析 `saPayload.Proposals[0]` 以查看选择了什么。
	// 获取转换。
	selProp := saPayload.Proposals[0]
	var prfID uint16
	var encrID uint16
	var encrKeyLenBits int
	var integID uint16
	var dhID uint16

	for _, t := range selProp.Transforms {
		switch t.Type {
		case ikev2.TransformTypeEncr:
			encrID = uint16(t.ID)
			for _, a := range t.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(a.Val)
				}
			}
		case ikev2.TransformTypeInteg:
			integID = uint16(t.ID)
		case ikev2.TransformTypePRF:
			prfID = uint16(t.ID)
		case ikev2.TransformTypeDH:
			dhID = uint16(t.ID)
		}
	}

	s.Logger.Debug(s.pfx("ePDG_SA_INIT: IKE SA 算法协商成功"),
		logger.String("encr", ikev2.EncrToString(encrID)),
		logger.Int("encr_key_bits", encrKeyLenBits),
		logger.String("integ", ikev2.IntegToString(integID)),
		logger.String("prf", ikev2.PRFToString(prfID)),
		logger.String("dh", ikev2.DHToString(dhID)),
	)

	// 设置加密实例
	s.PRFAlg, err = crypto.GetPRF(prfID)
	if err != nil {
		return fmt.Errorf("选择了不支持的 PRF: %d", prfID)
	}

	s.EncAlg, err = crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("选择了不支持的 Encr: %d", encrID)
	}
	s.ikeEncrID = encrID
	s.ikePRFID = prfID
	s.ikeDHID = dhID
	s.ikeEncrKeyLenBits = encrKeyLenBits
	s.ikeIsAEAD = encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	if s.ikeIsAEAD {
		s.ikeIntegID = 0
		s.IntegAlg, _ = crypto.GetIntegrityAlgorithm(0)
	} else {
		s.ikeIntegID = integID
		s.IntegAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("选择了不支持的 Integ: %d", integID)
		}
	}

	// 计算共享密钥
	if _, err := s.DH.ComputeSharedSecret(kePayload.KEData); err != nil {
		return fmt.Errorf("DH 计算失败: %v", err)
	}

	// 计算密钥
	s.Logger.Debug(s.pfx("正在生成密钥材料"))
	if err := s.GenerateIKESAKeys(s.nr); err != nil {
		return err
	}

	s.sendCookie = false
	return nil
}

func ParseRedirectData(data []byte) (string, error) {
	if len(data) < 1 {
		return "", errors.New("empty redirect data")
	}
	gwType := data[0]
	gwData := data[1:]

	switch gwType {
	case ikev2.RedirectGWIPv4: // IPv4
		if len(gwData) != 4 {
			return "", fmt.Errorf("invalid IPv4 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWIPv6: // IPv6
		if len(gwData) != 16 {
			return "", fmt.Errorf("invalid IPv6 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWFQDN: // FQDN
		return string(gwData), nil
	default:
		return "", fmt.Errorf("unknown gateway identity type: %d", gwType)
	}
}
