package database

import (
	"context"
	"time"
)

// Database 数据库接口，抽象不同数据库的操作
type Database interface {
	// 连接管理
	Connect(ctx context.Context) error
	Close() error
	Ping(ctx context.Context) error

	// 事务管理
	Begin(ctx context.Context) (Transaction, error)

	// 迁移管理
	Migrate(models ...interface{}) error

	// 基础CRUD操作
	Create(ctx context.Context, model interface{}) error
	Update(ctx context.Context, model interface{}) error
	Delete(ctx context.Context, model interface{}) error
	FindByID(ctx context.Context, id interface{}, model interface{}) error
	FindOne(ctx context.Context, condition interface{}, model interface{}) error
	FindAll(ctx context.Context, condition interface{}, models interface{}) error

	// 分页查询
	FindWithPagination(ctx context.Context, condition interface{}, models interface{}, offset, limit int) (int64, error)

	// 排序查询
	FindAllWithOrder(ctx context.Context, condition interface{}, models interface{}, orderBy string) error
	FindWithPaginationAndOrder(ctx context.Context, condition interface{}, models interface{}, offset, limit int, orderBy string) (int64, error)

	// 带参数的条件查询
	FindAllWithConditionAndOrder(ctx context.Context, condition string, args []interface{}, models interface{}, orderBy string) error
	FindWithConditionPaginationAndOrder(ctx context.Context, condition string, args []interface{}, models interface{}, offset, limit int, orderBy string) (int64, error)

	// 原生查询
	Raw(ctx context.Context, sql string, values ...interface{}) (interface{}, error)
	Exec(ctx context.Context, sql string, values ...interface{}) error

	// 批量操作
	CreateInBatches(ctx context.Context, models interface{}, batchSize int) error
	UpdateInBatches(ctx context.Context, models interface{}, batchSize int) error

	// 统计操作
	Count(ctx context.Context, condition interface{}, model interface{}) (int64, error)
	Exists(ctx context.Context, condition interface{}, model interface{}) (bool, error)
}

// Transaction 事务接口
type Transaction interface {
	// 基础CRUD操作（在事务中）
	Create(ctx context.Context, model interface{}) error
	Update(ctx context.Context, model interface{}) error
	Delete(ctx context.Context, model interface{}) error
	FindByID(ctx context.Context, id interface{}, model interface{}) error
	FindOne(ctx context.Context, condition interface{}, model interface{}) error
	FindAll(ctx context.Context, condition interface{}, models interface{}) error

	// 事务控制
	Commit() error
	Rollback() error
}

// Config 数据库配置
type Config struct {
	Type     string `json:"type"`     // 数据库类型: sqlite, mysql, postgres
	Host     string `json:"host"`     // 主机地址
	Port     int    `json:"port"`     // 端口
	Database string `json:"database"` // 数据库名称
	Username string `json:"username"` // 用户名
	Password string `json:"password"` // 密码
	SSLMode  string `json:"ssl_mode"` // SSL模式
	Charset  string `json:"charset"`  // 字符集

	// 连接池配置
	MaxOpenConns    int           `json:"max_open_conns"`     // 最大打开连接数
	MaxIdleConns    int           `json:"max_idle_conns"`     // 最大空闲连接数
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`  // 连接最大生存时间
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time"` // 连接最大空闲时间

	// SQLite特定配置
	FilePath string `json:"file_path"` // SQLite文件路径
}

// DatabaseFactory 数据库工厂接口
type DatabaseFactory interface {
	CreateDatabase(config *Config) (Database, error)
	SupportedTypes() []string
}
