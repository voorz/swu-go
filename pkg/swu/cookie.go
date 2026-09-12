package swu

import (
	"errors"

	"github.com/voorz/swu-go/pkg/logger"
)

var ErrCookieRequired = errors.New("需要重新发送带 COOKIE 的 IKE_SA_INIT")

// handleCookie 处理来自 ePDG 的 COOKIE 通知
// 当收到 COOKIE 时，需要在下次 IKE_SA_INIT 中包含该 COOKIE
//
// 兼顾策略：根据 COOKIE 重试次数决定是否重置 Nonce/KE
//   - 第 1 次收到 COOKIE：保持原始 Nonce/KE（标准 RFC 7296 行为），
//     大多数 ePDG 的 COOKIE 基于原始 Nonce/KE 计算
//   - 第 2+ 次收到 COOKIE：说明 ePDG 不接受原始组合，
//     重置 Nonce/KE 避免被判定为重复请求
func (s *Session) handleCookie(cookieData []byte) error {
	logger.Debug("收到 COOKIE，重新发送 IKE_SA_INIT", logger.Int("len", len(cookieData)))

	// 保存 cookie
	s.cookie = make([]byte, len(cookieData))
	copy(s.cookie, cookieData)
	s.sendCookie = true

	// 仅在重复收到 COOKIE 时重置 Nonce 和 DH
	if s.cookieRetryCount >= 1 {
		logger.Debug("COOKIE 重复重试，重置 Nonce 和 DH 生成新密钥材料", logger.Int("retry", s.cookieRetryCount))
		s.ni = nil
		s.DH = nil
	}

	return nil
}
