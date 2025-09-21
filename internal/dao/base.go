package dao

import (
	"context"
	"fmt"
	"reflect"
	"router-os/internal/database"
)

// BaseDAOImpl 基础DAO实现
type BaseDAOImpl[T any] struct {
	db        database.Database
	modelType reflect.Type
}

// NewBaseDAO 创建基础DAO实例
func NewBaseDAO[T any](db database.Database) BaseDAO[T] {
	var zero T
	modelType := reflect.TypeOf(zero)
	if modelType.Kind() == reflect.Ptr {
		modelType = modelType.Elem()
	}

	return &BaseDAOImpl[T]{
		db:        db,
		modelType: modelType,
	}
}

// Create 创建实体
func (dao *BaseDAOImpl[T]) Create(ctx context.Context, entity *T) error {
	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}
	return dao.db.Create(ctx, entity)
}

// Update 更新实体
func (dao *BaseDAOImpl[T]) Update(ctx context.Context, entity *T) error {
	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}
	return dao.db.Update(ctx, entity)
}

// Delete 删除实体
func (dao *BaseDAOImpl[T]) Delete(ctx context.Context, id interface{}) error {
	if id == nil {
		return fmt.Errorf("id cannot be nil")
	}

	// 创建一个空的实体实例用于删除
	entity := reflect.New(dao.modelType).Interface()

	// 先查找实体
	err := dao.db.FindByID(ctx, id, entity)
	if err != nil {
		return fmt.Errorf("failed to find entity with id %v: %w", id, err)
	}

	// 删除实体
	return dao.db.Delete(ctx, entity)
}

// FindByID 根据ID查找实体
func (dao *BaseDAOImpl[T]) FindByID(ctx context.Context, id interface{}) (*T, error) {
	if id == nil {
		return nil, fmt.Errorf("id cannot be nil")
	}

	entity := reflect.New(dao.modelType).Interface().(*T)
	err := dao.db.FindByID(ctx, id, entity)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// FindAll 查找所有实体
func (dao *BaseDAOImpl[T]) FindAll(ctx context.Context) ([]*T, error) {
	var entities []*T
	err := dao.db.FindAll(ctx, nil, &entities)
	if err != nil {
		return nil, err
	}

	return entities, nil
}

// FindByCondition 根据条件查找实体
func (dao *BaseDAOImpl[T]) FindByCondition(ctx context.Context, condition interface{}) ([]*T, error) {
	var entities []*T
	err := dao.db.FindAll(ctx, condition, &entities)
	if err != nil {
		return nil, err
	}

	return entities, nil
}

// FindOneByCondition 根据条件查找单个实体
func (dao *BaseDAOImpl[T]) FindOneByCondition(ctx context.Context, condition interface{}) (*T, error) {
	entity := reflect.New(dao.modelType).Interface().(*T)
	err := dao.db.FindOne(ctx, condition, entity)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// FindWithPagination 分页查询
func (dao *BaseDAOImpl[T]) FindWithPagination(ctx context.Context, condition interface{}, offset, limit int) ([]*T, int64, error) {
	var entities []*T
	total, err := dao.db.FindWithPagination(ctx, condition, &entities, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	return entities, total, nil
}

// Count 统计记录数
func (dao *BaseDAOImpl[T]) Count(ctx context.Context, condition interface{}) (int64, error) {
	entity := reflect.New(dao.modelType).Interface()
	return dao.db.Count(ctx, condition, entity)
}

// Exists 检查记录是否存在
func (dao *BaseDAOImpl[T]) Exists(ctx context.Context, condition interface{}) (bool, error) {
	entity := reflect.New(dao.modelType).Interface()
	return dao.db.Exists(ctx, condition, entity)
}

// CreateBatch 批量创建
func (dao *BaseDAOImpl[T]) CreateBatch(ctx context.Context, entities []*T) error {
	if len(entities) == 0 {
		return nil
	}

	return dao.db.CreateInBatches(ctx, entities, 100) // 默认批次大小为100
}

// UpdateBatch 批量更新
func (dao *BaseDAOImpl[T]) UpdateBatch(ctx context.Context, entities []*T) error {
	if len(entities) == 0 {
		return nil
	}

	// 由于GORM的批量更新限制，这里使用事务逐个更新
	return dao.WithTransaction(ctx, func(tx database.Transaction) error {
		for _, entity := range entities {
			if err := tx.Update(ctx, entity); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteBatch 批量删除
func (dao *BaseDAOImpl[T]) DeleteBatch(ctx context.Context, ids []interface{}) error {
	if len(ids) == 0 {
		return nil
	}

	// 使用事务逐个删除
	return dao.WithTransaction(ctx, func(tx database.Transaction) error {
		for _, id := range ids {
			entity := reflect.New(dao.modelType).Interface()
			if err := tx.FindByID(ctx, id, entity); err != nil {
				return fmt.Errorf("failed to find entity with id %v: %w", id, err)
			}
			if err := tx.Delete(ctx, entity); err != nil {
				return fmt.Errorf("failed to delete entity with id %v: %w", id, err)
			}
		}
		return nil
	})
}

// WithTransaction 执行事务操作
func (dao *BaseDAOImpl[T]) WithTransaction(ctx context.Context, fn func(tx database.Transaction) error) error {
	tx, err := dao.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
			panic(r)
		}
	}()

	if err := fn(tx); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("transaction failed: %w, rollback failed: %v", err, rollbackErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
