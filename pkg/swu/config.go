package swu

import (
	"github.com/voorz/swu-go/pkg/sim"
)

type Config struct {
	EpDGAddr  string
	EpDGPort  uint16 // 默认 500
	APN       string
	LocalAddr string // 传出接口 IP (通常自动检测)
	DNSServer string // 可选: 用于解析 ePDG 域名的 DNS 服务器 (host:port)

	SIM          sim.SIMProvider
	EnableDriver bool // 是否创建 TUN 和路由 (需要 root)

	// 数据平面模式: "tun" (默认，用户空间 ESP) 或 "xfrmi" (内核 XFRM offload)
	DataplaneMode string
	// XFRMI 模式专用配置
	XFRMIfID uint32 // XFRM interface ID (默认自动分配)

	// 可选的特定配置
	MCC       string
	MNC       string
	IMSI      string // 可选: 预设 IMSI，当 SIM.GetIMSI() 返回空时作为 fallback
	LocalPort uint16 // 本地 UDP 端口 (默认 500)
	// IKE SA 重认证间隔（秒），0 表示禁用
	// 默认 0 (不主动重认证，仅 Rekey)
	ReauthInterval int

	TUNName string // TUN 设备名 (默认自动分配)
	TUNMTU  int    // TUN MTU，0 表示使用默认值（默认 1358，已预留约 142B 的 ESP-in-UDP 封装开销）

	// XFRM SA 抗重放窗口大小（0 = 使用默认值 32）
	// 高延迟/乱序网络建议设为 128 或 256
	ReplayWindow int

	// 启用 ESN（Extended Sequence Numbers, RFC 4303 §2.2.1）
	// 64 位序列号，防止高速网络下 32 位 SN 溢出
	// 默认 false（VoWiFi 场景通常不需要）
	EnableESN bool

	EAPMACValidation bool

	EnableWiresharkKeyLog bool
	WiresharkKeyLogPath   string

	// RFC 5723: Session Resumption 跨会话凭证漂流保护
	ResumeTicket   []byte
	ResumeOldSKd   []byte
	OnTicketUpdate func(ticket, skd []byte)

	// RFC 4187: EAP-AKA Fast Re-authentication 跨会话快速重连
	// 从 ePDG 鉴权成功后提取的假名 ID 和密钥材料，用于下次断线重连时
	// 绕过物理 SIM 卡读取（AT+CSIM），实现 0-RTT 的极速软鉴权
	FastReauthID       string                                        // 来自 AT_NEXT_REAUTH_ID 的临时假名
	FastReauthMK       []byte                                        // Master Key (上次全量认证派生)
	FastReauthKAut     []byte                                        // K_Aut (用于 MAC 校验)
	FastReauthKEncr    []byte                                        // K_Encr (用于属性加密)
	OnFastReauthUpdate func(reauthID string, mk, kAut, kEncr []byte) // 外层持久化回调

	TransportFactory func(local string, remote string) (Transport, error)
	TUNFactory       func(name string) (TUN, error)
	NetTools         NetTools

	// OnReady is invoked once the Child SA dataplane is ready for inner traffic.
	OnReady func()

	// 支持自定义的 IKEv2 和 ESP 协商组合列表。如果留空，将使用内置的大而全强兼容默认套件。
	// 示例：[]string{"aes256gcm16-prfsha384-ecp384", "aes128-sha256-modp2048"}
	IKEProposals []string
	ESPProposals []string

	// ESPRekeyPFS controls PFS (Perfect Forward Secrecy) for Child SA.
	// Set to a DH group number (e.g. 14 for MODP-2048) to include a DH
	// transform in ESP proposals during IKE_AUTH and CREATE_CHILD_SA.
	// 0 = disabled (no PFS). This aligns with strongSwan's rekey_pfs option.
	ESPRekeyPFS int

	// --- 运营商预设字段 (v1.5.5 YAML carrier presets) ---

	// DPDInterval is the Dead Peer Detection interval in seconds.
	// 0 = disabled (DPD not started). Typical value: 600.
	DPDInterval int

	// NATKeepaliveInterval is the NAT-T keepalive interval in seconds.
	// 0 = use default (20s). Typical value: 20.
	NATKeepaliveInterval int

	// DeviceIdentityEnabled controls whether the DEVICE_IDENTITY notify is sent.
	// nil = default (disabled, aligning with v1.5.5 baseline).
	// Pointer to true/false allows explicit override per carrier.
	DeviceIdentityEnabled *bool

	// AKAChallengeMode controls EAP-AKA challenge behavior.
	// "standard" (default), "minimal", "checkcode", "omit".
	AKAChallengeMode string

	// TicketRequestEnabled controls whether N(TICKET_REQUEST) is sent in
	// the first IKE_AUTH request (RFC 5723 §3.1).
	// nil = default (disabled, compatible with Three UK ePDG).
	// Pointer to true/false allows explicit override per carrier (e.g. 3HK needs it).
	TicketRequestEnabled *bool

	// CPInFirstAuth controls whether CP(CFG_REQUEST) is included in the first
	// IKE_AUTH request.
	// nil = default (true, send CP in first AUTH).
	// Pointer to false allows carriers whose ePDG rejects CP in the first AUTH.
	CPInFirstAuth *bool

	// CPInFinalAuth controls whether CP(CFG_REQUEST) is included in the final
	// AUTH message (after EAP Success, before Child SA creation).
	// nil = default (true, send CP in final AUTH when CP was not sent in first AUTH).
	// Pointer to false allows carriers whose ePDG auto-returns CP(CFG_REPLY)
	// without being asked (e.g. 3HK community behavior).
	CPInFinalAuth *bool

	// EAPIdentity overrides the NAI used for EAP-AKA. When non-empty, this
	// takes priority over the IMSI-derived NAI from buildNAI(). This is
	// how a provisioned ISIM IMPI (e.g. "user@ims.mnc003.mcc454.3gppnetwork.org")
	// from the上层 vowifi-core identity package flows into the EAP exchange.
	// Empty = auto-derive from IMSI via buildNAI().
	EAPIdentity string

	// IMEI is the device IMEI used for AT_CHECKCODE computation when the
	// SIM provider does not implement sim.IMEIProvider.
	// When empty and SIM doesn't implement IMEIProvider, checkcode falls
	// back to IMSI-derived checkcode.
	IMEI string

	// IPStack controls which IP stack the IKE/IPsec tunnel uses.
	// "ipv4", "ipv6", "ipv4v6". Empty = auto (both).
	IPStack string

	// DeviceModel is a carrier-specific device model hint used for
	// identity derivation (e.g. "rmx3366", "iphone15,4").
	DeviceModel string

	// DeviceID is the device identifier used for log prefixing.
	DeviceID string
	// TraceID is the request trace identifier used for log correlation.
	TraceID string

	// IKERetryCount overrides the default IKE retransmission count.
	// 0 = use default (5, aligned with strongSwan retransmit_tries).
	IKERetryCount int

	// CookiePayloadType controls the IKE payload type for COOKIE Notify in IKE_SA_INIT.
	// RFC 7296 §2.6 标准为 Notify(41)，但少数 ePDG 要求 SA(33)。
	// "notify" (默认) = 使用标准 N(41)
	// "sa" = 使用 SA(33)，兼容某些非标 ePDG
	CookiePayloadType string

	// AutoPRF controls whether to automatically derive the PRF Transform
	// from the Integrity algorithm when no explicit PRF is configured.
	// true (默认): 从 Integrity 算法自动推导 PRF（兼容要求显式 PRF 的 ePDG）。
	// false: 不自动推导，让 ePDG 从 Integrity 推导 PRF。
	AutoPRF bool
}
