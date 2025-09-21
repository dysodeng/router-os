package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// LogLevel 日志级别
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelFatal
)

// String 返回日志级别的字符串表示
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger 日志记录器
type Logger struct {
	level   LogLevel
	logger  *log.Logger
	file    *os.File
	mu      sync.RWMutex
	enabled bool
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// GetLogger 获取默认日志记录器
func GetLogger() *Logger {
	once.Do(func() {
		defaultLogger = NewLogger(LogLevelInfo, "")
	})
	return defaultLogger
}

// NewLogger 创建新的日志记录器
func NewLogger(level LogLevel, filename string) *Logger {
	logger := &Logger{
		level:   level,
		enabled: true,
	}

	var writer io.Writer = os.Stdout

	if filename != "" {
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("无法打开日志文件 %s: %v\n", filename, err)
			writer = os.Stdout
		} else {
			logger.file = file
			writer = io.MultiWriter(os.Stdout, file)
		}
	}

	logger.logger = log.New(writer, "", 0)
	return logger
}

// SetLevel 设置日志级别
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetEnabled 设置是否启用日志
func (l *Logger) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

// Close 关闭日志记录器
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// log 记录日志
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if !l.enabled || level < l.level {
		return
	}

	// 使用中国时区格式化时间
	loc, _ := time.LoadLocation("Asia/Shanghai")
	timestamp := time.Now().In(loc).Format("2006-01-02 15:04:05 CST")
	message := fmt.Sprintf(format, args...)
	logLine := fmt.Sprintf("[%s] [%s] %s", timestamp, level.String(), message)

	l.logger.Println(logLine)
}

// Debug 记录调试日志
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LogLevelDebug, format, args...)
}

// Info 记录信息日志
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LogLevelInfo, format, args...)
}

// Warn 记录警告日志
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LogLevelWarn, format, args...)
}

// Error 记录错误日志
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LogLevelError, format, args...)
}

// Fatal 记录致命错误日志并退出程序
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(LogLevelFatal, format, args...)
	os.Exit(1)
}

// 全局日志函数
func Debug(format string, args ...interface{}) {
	GetLogger().Debug(format, args...)
}

func Info(format string, args ...interface{}) {
	GetLogger().Info(format, args...)
}

func Warn(format string, args ...interface{}) {
	GetLogger().Warn(format, args...)
}

func Error(format string, args ...interface{}) {
	GetLogger().Error(format, args...)
}

func Fatal(format string, args ...interface{}) {
	GetLogger().Fatal(format, args...)
}

// ParseLogLevel 解析日志级别字符串
func ParseLogLevel(level string) LogLevel {
	switch level {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn":
		return LogLevelWarn
	case "error":
		return LogLevelError
	case "fatal":
		return LogLevelFatal
	default:
		return LogLevelInfo
	}
}
