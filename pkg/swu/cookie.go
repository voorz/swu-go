package swu

import (
	"errors"

	"github.com/voorz/swu-go/pkg/logger"
)

var ErrCookieRequired = errors.New("需要重新发送带 COOKIE 的 IKE_SA_INIT")

// handleCookie 处理来自 ePDG 的 COOKIE 通知
// 当收到 COOKIE 时，需要在下次 IKE_SA_INIT 中包含该 COOKIE
// 同时重置 Nonce 和 KE，使重发请求携带新的密钥材料，
// 避免 ePDG 将重复请求视为异常并再次返回 COOKIE。
func (s *Session) handleCookie(cookieData []byte) error {
	logger.Debug("收到 COOKIE，重新发送 IKE_SA_INIT", logger.Int("len", len(cookieData)))

	// 保存 cookie
	s.cookie = make([]byte, len(cookieData))
	copy(s.cookie, cookieData)
	s.sendCookie = true

	// 重置 Nonce 和 DH，使下次 buildIKESAInitPacket 重新生成
	s.ni = nil
	s.DH = nil

	return nil
}
