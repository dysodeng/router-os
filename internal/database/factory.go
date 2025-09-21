package database

import (
	"fmt"
	"strings"
)

// DefaultFactory 默认数据库工厂实现
type DefaultFactory struct {
	drivers map[string]func(*Config) (Database, error)
}

// NewDefaultFactory 创建默认数据库工厂
func NewDefaultFactory() *DefaultFactory {
	factory := &DefaultFactory{
		drivers: make(map[string]func(*Config) (Database, error)),
	}

	// 注册SQLite驱动
	factory.RegisterDriver("sqlite", NewSQLiteDatabase)

	return factory
}

// RegisterDriver 注册数据库驱动
func (f *DefaultFactory) RegisterDriver(dbType string, creator func(*Config) (Database, error)) {
	f.drivers[strings.ToLower(dbType)] = creator
}

// CreateDatabase 创建数据库实例
func (f *DefaultFactory) CreateDatabase(config *Config) (Database, error) {
	dbType := strings.ToLower(config.Type)
	creator, exists := f.drivers[dbType]
	if !exists {
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}

	return creator(config)
}

// SupportedTypes 返回支持的数据库类型
func (f *DefaultFactory) SupportedTypes() []string {
	types := make([]string, 0, len(f.drivers))
	for dbType := range f.drivers {
		types = append(types, dbType)
	}
	return types
}

// 全局工厂实例
var globalFactory = NewDefaultFactory()

// GetFactory 获取全局数据库工厂
func GetFactory() DatabaseFactory {
	return globalFactory
}

// RegisterDriver 注册数据库驱动到全局工厂
func RegisterDriver(dbType string, creator func(*Config) (Database, error)) {
	globalFactory.RegisterDriver(dbType, creator)
}

// CreateDatabase 使用全局工厂创建数据库实例
func CreateDatabase(config *Config) (Database, error) {
	return globalFactory.CreateDatabase(config)
}
