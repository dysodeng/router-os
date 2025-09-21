package dao

import (
	"context"
	"fmt"
	"router-os/internal/database"
)

// DefaultDAOManager 默认DAO管理器实现
type DefaultDAOManager struct {
	db          database.Database
	initialized bool
}

// NewDAOManager 创建DAO管理器
func NewDAOManager(db database.Database) DAOManager {
	return &DefaultDAOManager{
		db: db,
	}
}

// GetDatabase 获取数据库实例
func (m *DefaultDAOManager) GetDatabase() database.Database {
	return m.db
}

// Initialize 初始化DAO管理器
func (m *DefaultDAOManager) Initialize() error {
	if m.initialized {
		return nil
	}

	// 连接数据库
	ctx := context.Background()
	if err := m.db.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// 检查数据库连接
	if err := m.db.Ping(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	m.initialized = true
	return nil
}

// Close 关闭DAO管理器
func (m *DefaultDAOManager) Close() error {
	if !m.initialized {
		return nil
	}

	if err := m.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	m.initialized = false
	return nil
}

// IsInitialized 检查是否已初始化
func (m *DefaultDAOManager) IsInitialized() bool {
	return m.initialized
}

// RepositoryImpl Repository接口的默认实现
type RepositoryImpl[T any] struct {
	*BaseDAOImpl[T]
}

// 确保RepositoryImpl实现了Repository接口
var _ Repository[any] = (*RepositoryImpl[any])(nil)

// DAOFactory DAO工厂，用于创建各种DAO实例
type DAOFactory struct {
	manager DAOManager
}

// NewDAOFactory 创建DAO工厂
func NewDAOFactory(manager DAOManager) *DAOFactory {
	return &DAOFactory{
		manager: manager,
	}
}

// GetManager 获取DAO管理器
func (f *DAOFactory) GetManager() DAOManager {
	return f.manager
}

// GetDatabase 获取数据库实例
func (f *DAOFactory) GetDatabase() database.Database {
	return f.manager.GetDatabase()
}

// CreateDAO 创建指定类型的DAO（独立函数）
func CreateDAO[T any](manager DAOManager) BaseDAO[T] {
	return NewBaseDAO[T](manager.GetDatabase())
}

// CreateRepository 创建指定类型的Repository（独立函数）
func CreateRepository[T any](manager DAOManager) Repository[T] {
	return &RepositoryImpl[T]{
		BaseDAOImpl: &BaseDAOImpl[T]{
			db: manager.GetDatabase(),
		},
	}
}

// CreateDAOWithFactory 使用工厂创建DAO
func CreateDAOWithFactory[T any](factory *DAOFactory) BaseDAO[T] {
	return CreateDAO[T](factory.manager)
}

// CreateRepositoryWithFactory 使用工厂创建Repository
func CreateRepositoryWithFactory[T any](factory *DAOFactory) Repository[T] {
	return CreateRepository[T](factory.manager)
}
