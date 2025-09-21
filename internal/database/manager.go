package database

import (
	"context"
	"fmt"
	"sync"
)

// Manager 数据库管理器
type Manager struct {
	config   *Config
	database Database
	factory  DatabaseFactory
	mu       sync.RWMutex
}

// NewManager 创建数据库管理器
func NewManager(config *Config) *Manager {
	return &Manager{
		config:  config,
		factory: GetFactory(),
	}
}

// Initialize 初始化数据库连接
func (m *Manager) Initialize(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.database != nil {
		return nil // 已经初始化
	}

	// 创建数据库实例
	db, err := m.factory.CreateDatabase(m.config)
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}

	// 连接数据库
	if err := db.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// 检查连接
	if err := db.Ping(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	m.database = db
	return nil
}

// GetDatabase 获取数据库实例
func (m *Manager) GetDatabase() Database {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.database
}

// Close 关闭数据库连接
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.database == nil {
		return nil
	}

	err := m.database.Close()
	m.database = nil
	return err
}

// Migrate 执行数据库迁移
func (m *Manager) Migrate(models ...interface{}) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.database == nil {
		return fmt.Errorf("database not initialized")
	}

	return m.database.Migrate(models...)
}

// IsInitialized 检查是否已初始化
func (m *Manager) IsInitialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.database != nil
}

// GetConfig 获取数据库配置
func (m *Manager) GetConfig() *Config {
	return m.config
}

// UpdateConfig 更新数据库配置（需要重新初始化）
func (m *Manager) UpdateConfig(config *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 如果数据库已初始化，先关闭
	if m.database != nil {
		if err := m.database.Close(); err != nil {
			return fmt.Errorf("failed to close existing database: %w", err)
		}
		m.database = nil
	}

	m.config = config
	return nil
}

// GetDefaultConfig 获取默认数据库配置
func GetDefaultConfig() *Config {
	return &Config{
		Type:            "sqlite",
		FilePath:        "data/router-os.db",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 3600, // 1小时
		ConnMaxIdleTime: 1800, // 30分钟
	}
}

// 全局数据库管理器实例
var globalManager *Manager
var globalManagerOnce sync.Once

// GetGlobalManager 获取全局数据库管理器
func GetGlobalManager() *Manager {
	globalManagerOnce.Do(func() {
		globalManager = NewManager(GetDefaultConfig())
	})
	return globalManager
}

// InitializeGlobalManager 初始化全局数据库管理器
func InitializeGlobalManager(ctx context.Context, config *Config) error {
	if config != nil {
		globalManager = NewManager(config)
	} else {
		globalManager = NewManager(GetDefaultConfig())
	}

	return globalManager.Initialize(ctx)
}

// CloseGlobalManager 关闭全局数据库管理器
func CloseGlobalManager() error {
	if globalManager != nil {
		return globalManager.Close()
	}
	return nil
}
