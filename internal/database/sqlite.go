package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SQLiteDatabase SQLite数据库实现
type SQLiteDatabase struct {
	db     *gorm.DB
	config *Config
}

// SQLiteTransaction SQLite事务实现
type SQLiteTransaction struct {
	tx *gorm.DB
}

// NewSQLiteDatabase 创建SQLite数据库实例
func NewSQLiteDatabase(config *Config) (Database, error) {
	if config.FilePath == "" {
		config.FilePath = "router-os.db"
	}

	// 确保目录存在
	dir := filepath.Dir(config.FilePath)
	if dir != "." && dir != "" {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return nil, err
		}
	}

	return &SQLiteDatabase{
		config: config,
	}, nil
}

// Connect 连接数据库
func (s *SQLiteDatabase) Connect(ctx context.Context) error {
	// 配置GORM日志级别
	logLevel := logger.Silent
	if s.config.Type == "debug" {
		logLevel = logger.Info
	}

	// 打开数据库连接
	db, err := gorm.Open(sqlite.Open(s.config.FilePath), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to SQLite database: %w", err)
	}

	s.db = db

	// 配置连接池
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	if s.config.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(s.config.MaxOpenConns)
	} else {
		sqlDB.SetMaxOpenConns(10) // 默认值
	}

	if s.config.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(s.config.MaxIdleConns)
	} else {
		sqlDB.SetMaxIdleConns(5) // 默认值
	}

	if s.config.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(s.config.ConnMaxLifetime)
	} else {
		sqlDB.SetConnMaxLifetime(time.Hour) // 默认1小时
	}

	if s.config.ConnMaxIdleTime > 0 {
		sqlDB.SetConnMaxIdleTime(s.config.ConnMaxIdleTime)
	} else {
		sqlDB.SetConnMaxIdleTime(time.Minute * 30) // 默认30分钟
	}

	return nil
}

// Close 关闭数据库连接
func (s *SQLiteDatabase) Close() error {
	if s.db == nil {
		return nil
	}

	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}

	return sqlDB.Close()
}

// Ping 检查数据库连接
func (s *SQLiteDatabase) Ping(ctx context.Context) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}

	return sqlDB.PingContext(ctx)
}

// Begin 开始事务
func (s *SQLiteDatabase) Begin(ctx context.Context) (Transaction, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not connected")
	}

	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}

	return &SQLiteTransaction{tx: tx}, nil
}

// Migrate 执行数据库迁移
func (s *SQLiteDatabase) Migrate(models ...interface{}) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	return s.db.AutoMigrate(models...)
}

// Create 创建记录
func (s *SQLiteDatabase) Create(ctx context.Context, model interface{}) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	result := s.db.WithContext(ctx).Create(model)
	return result.Error
}

// Update 更新记录
func (s *SQLiteDatabase) Update(ctx context.Context, model interface{}) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	result := s.db.WithContext(ctx).Save(model)
	return result.Error
}

// Delete 删除记录
func (s *SQLiteDatabase) Delete(ctx context.Context, model interface{}) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	result := s.db.WithContext(ctx).Delete(model)
	return result.Error
}

// FindByID 根据ID查找记录
func (s *SQLiteDatabase) FindByID(ctx context.Context, id interface{}, model interface{}) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	result := s.db.WithContext(ctx).First(model, id)
	return result.Error
}

// FindOne 查找单条记录
func (s *SQLiteDatabase) FindOne(ctx context.Context, condition interface{}, model interface{}) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	result := s.db.WithContext(ctx).Where(condition).First(model)
	return result.Error
}

// FindAll 查找所有记录
func (s *SQLiteDatabase) FindAll(ctx context.Context, condition interface{}, models interface{}) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	result := s.db.WithContext(ctx).Where(condition).Find(models)
	return result.Error
}

// FindWithPagination 分页查询
func (s *SQLiteDatabase) FindWithPagination(ctx context.Context, condition interface{}, models interface{}, offset, limit int) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not connected")
	}

	var total int64

	// 先获取总数
	countResult := s.db.WithContext(ctx).Model(models).Where(condition).Count(&total)
	if countResult.Error != nil {
		return 0, countResult.Error
	}

	// 再获取分页数据
	result := s.db.WithContext(ctx).Where(condition).Offset(offset).Limit(limit).Find(models)
	return total, result.Error
}

// Raw 执行原生查询
func (s *SQLiteDatabase) Raw(ctx context.Context, sql string, values ...interface{}) (interface{}, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not connected")
	}

	result := s.db.WithContext(ctx).Raw(sql, values...)
	return result, result.Error
}

// Exec 执行原生SQL
func (s *SQLiteDatabase) Exec(ctx context.Context, sql string, values ...interface{}) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	result := s.db.WithContext(ctx).Exec(sql, values...)
	return result.Error
}

// CreateInBatches 批量创建
func (s *SQLiteDatabase) CreateInBatches(ctx context.Context, models interface{}, batchSize int) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	result := s.db.WithContext(ctx).CreateInBatches(models, batchSize)
	return result.Error
}

// UpdateInBatches 批量更新
func (s *SQLiteDatabase) UpdateInBatches(ctx context.Context, models interface{}, batchSize int) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	// GORM没有直接的批量更新方法，这里需要自定义实现
	// 暂时返回未实现错误
	return fmt.Errorf("batch update not implemented for SQLite")
}

// Count 统计记录数
func (s *SQLiteDatabase) Count(ctx context.Context, condition interface{}, model interface{}) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not connected")
	}

	var count int64
	result := s.db.WithContext(ctx).Model(model).Where(condition).Count(&count)
	return count, result.Error
}

// Exists 检查记录是否存在
func (s *SQLiteDatabase) Exists(ctx context.Context, condition interface{}, model interface{}) (bool, error) {
	count, err := s.Count(ctx, condition, model)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// SQLiteTransaction 事务方法实现

// Create 在事务中创建记录
func (t *SQLiteTransaction) Create(ctx context.Context, model interface{}) error {
	result := t.tx.WithContext(ctx).Create(model)
	return result.Error
}

// Update 在事务中更新记录
func (t *SQLiteTransaction) Update(ctx context.Context, model interface{}) error {
	result := t.tx.WithContext(ctx).Save(model)
	return result.Error
}

// Delete 在事务中删除记录
func (t *SQLiteTransaction) Delete(ctx context.Context, model interface{}) error {
	result := t.tx.WithContext(ctx).Delete(model)
	return result.Error
}

// FindByID 在事务中根据ID查找记录
func (t *SQLiteTransaction) FindByID(ctx context.Context, id interface{}, model interface{}) error {
	result := t.tx.WithContext(ctx).First(model, id)
	return result.Error
}

// FindOne 在事务中查找单条记录
func (t *SQLiteTransaction) FindOne(ctx context.Context, condition interface{}, model interface{}) error {
	result := t.tx.WithContext(ctx).Where(condition).First(model)
	return result.Error
}

// FindAll 在事务中查找所有记录
func (t *SQLiteTransaction) FindAll(ctx context.Context, condition interface{}, models interface{}) error {
	result := t.tx.WithContext(ctx).Where(condition).Find(models)
	return result.Error
}

// Commit 提交事务
func (t *SQLiteTransaction) Commit() error {
	result := t.tx.Commit()
	return result.Error
}

// Rollback 回滚事务
func (t *SQLiteTransaction) Rollback() error {
	result := t.tx.Rollback()
	return result.Error
}
