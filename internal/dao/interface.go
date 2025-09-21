package dao

import (
	"context"
	"router-os/internal/database"
)

// BaseDAO 基础DAO接口，定义通用的数据访问方法
type BaseDAO[T any] interface {
	// 基础CRUD操作
	Create(ctx context.Context, entity *T) error
	Update(ctx context.Context, entity *T) error
	Delete(ctx context.Context, id interface{}) error
	FindByID(ctx context.Context, id interface{}) (*T, error)
	FindAll(ctx context.Context) ([]*T, error)

	// 条件查询
	FindByCondition(ctx context.Context, condition interface{}) ([]*T, error)
	FindOneByCondition(ctx context.Context, condition interface{}) (*T, error)

	// 分页查询
	FindWithPagination(ctx context.Context, condition interface{}, offset, limit int) ([]*T, int64, error)

	// 统计操作
	Count(ctx context.Context, condition interface{}) (int64, error)
	Exists(ctx context.Context, condition interface{}) (bool, error)

	// 批量操作
	CreateBatch(ctx context.Context, entities []*T) error
	UpdateBatch(ctx context.Context, entities []*T) error
	DeleteBatch(ctx context.Context, ids []interface{}) error
}

// TransactionalDAO 支持事务的DAO接口
type TransactionalDAO interface {
	// 事务操作
	WithTransaction(ctx context.Context, fn func(tx database.Transaction) error) error
}

// DAOManager DAO管理器接口
type DAOManager interface {
	// 获取数据库实例
	GetDatabase() database.Database

	// 初始化所有DAO
	Initialize() error

	// 关闭资源
	Close() error
}

// Repository 仓储模式接口，用于复杂的业务查询
type Repository[T any] interface {
	BaseDAO[T]
	TransactionalDAO

	// 业务相关的查询方法可以在具体实现中定义
}
