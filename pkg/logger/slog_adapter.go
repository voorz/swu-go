package logger

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// SlogAdapter is a slog.Handler that bridges slog logs to the zap logger.
// This allows libraries using log/slog (e.g. sipgo) to have their output
// routed through the project's zap-based logging system.
type SlogAdapter struct {
	logger      *zap.Logger
	callerChain []string
}

// NewSlogHandler creates a slog handler that bridges to the given zap logger.
// If logger is nil, falls back to the global swu-go logger.
func NewSlogHandler(l *zap.Logger) *SlogAdapter {
	if l == nil {
		l = Get()
	}
	return &SlogAdapter{
		logger:      l.WithOptions(zap.WithCaller(false)),
		callerChain: nil,
	}
}

// Enabled implements slog.Handler.
func (h *SlogAdapter) Enabled(_ context.Context, level slog.Level) bool {
	return true
}

// Handle implements slog.Handler, routing the record to zap.
func (h *SlogAdapter) Handle(_ context.Context, r slog.Record) error {
	fields := make([]zap.Field, 0, r.NumAttrs())
	errText := ""
	src := callerFromPC(r.PC)
	callers := make([]string, 0, len(h.callerChain)+2)
	callers = append(callers, h.callerChain...)
	r.Attrs(func(a slog.Attr) bool {
		if strings.TrimSpace(a.Key) == "" {
			return true
		}
		if a.Key == "caller" {
			if v := strings.TrimSpace(fmt.Sprint(a.Value.Any())); v != "" {
				callers = append(callers, v)
			}
			return true
		}
		if a.Key == "error" {
			errText = strings.TrimSpace(fmt.Sprint(a.Value.Any()))
		}
		fields = append(fields, zap.Any(a.Key, a.Value.Any()))
		return true
	})

	if uniq := dedupeNonEmpty(callers); len(uniq) > 0 {
		fields = append(fields, zap.String("caller", uniq[len(uniq)-1]))
		if len(uniq) > 1 {
			fields = append(fields, zap.String("caller_chain", strings.Join(uniq, " -> ")))
		}
	}

	level := r.Level
	msg := r.Message
	if strings.EqualFold(strings.TrimSpace(msg), "Read error") {
		errLower := strings.ToLower(errText)
		if strings.Contains(errLower, "connection reset by peer") ||
			strings.Contains(errLower, "connection timed out") ||
			strings.Contains(errLower, "i/o timeout") ||
			strings.Contains(errLower, "use of closed network connection") ||
			strings.Contains(errLower, "broken pipe") ||
			strings.Contains(errLower, "eof") {
			msg = "SIP TCP 通道读异常"
			if strings.Contains(errLower, "use of closed network connection") || strings.Contains(errLower, "eof") {
				level = slog.LevelDebug
			} else {
				level = slog.LevelWarn
			}
		}
	}

	h.writeWithCaller(toZapLevel(level), r.Time, msg, fields, src)
	return nil
}

// WithAttrs implements slog.Handler.
func (h *SlogAdapter) WithAttrs(attrs []slog.Attr) slog.Handler {
	fields := make([]zap.Field, 0, len(attrs))
	callers := make([]string, 0, len(h.callerChain)+len(attrs))
	callers = append(callers, h.callerChain...)
	for _, a := range attrs {
		if strings.TrimSpace(a.Key) == "" {
			continue
		}
		if a.Key == "caller" {
			if v := strings.TrimSpace(fmt.Sprint(a.Value.Any())); v != "" {
				callers = append(callers, v)
			}
			continue
		}
		fields = append(fields, zap.Any(a.Key, a.Value.Any()))
	}
	return &SlogAdapter{
		logger:      h.logger.With(fields...),
		callerChain: callers,
	}
}

// WithGroup implements slog.Handler.
func (h *SlogAdapter) WithGroup(name string) slog.Handler {
	return &SlogAdapter{
		logger:      h.logger.Named(name),
		callerChain: append([]string(nil), h.callerChain...),
	}
}

func dedupeNonEmpty(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func callerFromPC(pc uintptr) zapcore.EntryCaller {
	if pc == 0 {
		return zapcore.EntryCaller{}
	}
	frame, _ := runtime.CallersFrames([]uintptr{pc}).Next()
	if frame.File == "" || frame.Line <= 0 {
		return zapcore.EntryCaller{}
	}
	return zapcore.EntryCaller{
		Defined:  true,
		PC:       frame.PC,
		File:     frame.File,
		Line:     frame.Line,
		Function: frame.Function,
	}
}

func toZapLevel(level slog.Level) zapcore.Level {
	switch {
	case level <= slog.LevelDebug:
		return zapcore.DebugLevel
	case level < slog.LevelWarn:
		return zapcore.InfoLevel
	case level < slog.LevelError:
		return zapcore.WarnLevel
	default:
		return zapcore.ErrorLevel
	}
}

func (h *SlogAdapter) writeWithCaller(level zapcore.Level, ts time.Time, msg string, fields []zap.Field, caller zapcore.EntryCaller) {
	core := h.logger.Core()
	entry := zapcore.Entry{
		Level:   level,
		Time:    ts,
		Message: msg,
		Caller:  caller,
	}
	if ce := core.Check(entry, nil); ce != nil {
		ce.Write(fields...)
	}
}
