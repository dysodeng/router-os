# 数据库抽象层使用说明

本文档介绍如何使用路由器操作系统项目中的数据库抽象层和DAO层。

## 架构概述

数据库抽象层采用分层架构设计：

1. **Database Interface Layer** (`internal/database/interface.go`) - 数据库接口抽象层
2. **Database Implementation Layer** (`internal/database/sqlite.go`) - 具体数据库实现（SQLite）
3. **Database Factory Layer** (`internal/database/factory.go`) - 数据库工厂
4. **Database Manager Layer** (`internal/database/manager.go`) - 数据库管理器
5. **DAO Interface Layer** (`internal/dao/interface.go`) - DAO接口抽象层
6. **DAO Implementation Layer** (`internal/dao/base.go`) - DAO基础实现
7. **DAO Manager Layer** (`internal/dao/manager.go`) - DAO管理器

## 主要特性

- **数据库抽象**: 支持多种数据库类型（当前支持SQLite，可扩展MySQL、PostgreSQL等）
- **ORM集成**: 使用GORM作为ORM框架
- **事务支持**: 完整的事务管理功能
- **泛型支持**: 使用Go泛型提供类型安全的DAO操作
- **连接池管理**: 自动管理数据库连接池
- **批量操作**: 支持批量创建、更新、删除
- **分页查询**: 内置分页查询支持

## 快速开始

### 1. 定义数据模型

```go
type RouterConfig struct {
    ID        uint      `gorm:"primaryKey" json:"id"`
    Name      string    `gorm:"uniqueIndex;not null" json:"name"`
    Value     string    `gorm:"type:text" json:"value"`
    Enabled   bool      `gorm:"default:true" json:"enabled"`
    CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
    UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}
```

### 2. 初始化数据库

```go
import (
    "context"
    "router-os/internal/database"
    "router-os/internal/dao"
)

func initDatabase() error {
    ctx := context.Background()
    
    // 创建数据库配置
    config := &database.Config{
        Type:            "sqlite",
        FilePath:        "data/router-os.db",
        MaxOpenConns:    10,
        MaxIdleConns:    5,
        ConnMaxLifetime: time.Hour,
        ConnMaxIdleTime: time.Minute * 30,
    }
    
    // 初始化全局数据库管理器
    if err := database.InitializeGlobalManager(ctx, config); err != nil {
        return err
    }
    
    // 执行数据库迁移
    manager := database.GetGlobalManager()
    return manager.Migrate(&RouterConfig{})
}
```

### 3. 使用DAO进行数据操作

```go
func useDAO() error {
    ctx := context.Background()
    
    // 获取数据库管理器
    dbManager := database.GetGlobalManager()
    
    // 创建DAO管理器
    daoManager := dao.NewDAOManager(dbManager.GetDatabase())
    if err := daoManager.Initialize(); err != nil {
        return err
    }
    defer daoManager.Close()
    
    // 创建DAO实例
    configDAO := dao.CreateDAO[RouterConfig](daoManager)
    
    // 创建记录
    config := &RouterConfig{
        Name:    "hostname",
        Value:   "router-01",
        Enabled: true,
    }
    
    if err := configDAO.Create(ctx, config); err != nil {
        return err
    }
    
    // 查询记录
    foundConfig, err := configDAO.FindByID(ctx, config.ID)
    if err != nil {
        return err
    }
    
    // 更新记录
    foundConfig.Value = "router-02"
    if err := configDAO.Update(ctx, foundConfig); err != nil {
        return err
    }
    
    // 条件查询
    enabledConfigs, err := configDAO.FindByCondition(ctx, map[string]interface{}{
        "enabled": true,
    })
    if err != nil {
        return err
    }
    
    // 分页查询
    configs, total, err := configDAO.FindWithPagination(ctx, nil, 0, 10)
    if err != nil {
        return err
    }
    
    fmt.Printf("Found %d configs, total: %d\n", len(configs), total)
    
    return nil
}
```

### 4. 使用事务

```go
func useTransaction() error {
    ctx := context.Background()
    
    // 创建Repository（支持事务）
    dbManager := database.GetGlobalManager()
    daoManager := dao.NewDAOManager(dbManager.GetDatabase())
    repository := dao.CreateRepository[RouterConfig](daoManager)
    
    // 执行事务
    return repository.WithTransaction(ctx, func(tx database.Transaction) error {
        // 在事务中创建多个配置
        configs := []*RouterConfig{
            {Name: "config1", Value: "value1"},
            {Name: "config2", Value: "value2"},
        }
        
        for _, config := range configs {
            if err := tx.Create(ctx, config); err != nil {
                return err // 自动回滚
            }
        }
        
        return nil // 自动提交
    })
}
```

## 配置选项

### 数据库配置

```go
type Config struct {
    Type     string        // 数据库类型: sqlite, mysql, postgres
    Host     string        // 主机地址
    Port     int           // 端口
    Database string        // 数据库名称
    Username string        // 用户名
    Password string        // 密码
    SSLMode  string        // SSL模式
    Charset  string        // 字符集
    
    // 连接池配置
    MaxOpenConns    int           // 最大打开连接数
    MaxIdleConns    int           // 最大空闲连接数
    ConnMaxLifetime time.Duration // 连接最大生存时间
    ConnMaxIdleTime time.Duration // 连接最大空闲时间
    
    // SQLite特定配置
    FilePath string // SQLite文件路径
}
```

### 默认配置

```go
config := database.GetDefaultConfig()
// 等同于:
// &Config{
//     Type:            "sqlite",
//     FilePath:        "data/router-os.db",
//     MaxOpenConns:    10,
//     MaxIdleConns:    5,
//     ConnMaxLifetime: time.Hour,
//     ConnMaxIdleTime: time.Minute * 30,
// }
```

## 扩展支持

### 添加新的数据库类型

1. 实现 `Database` 接口
2. 注册到工厂

```go
// 实现MySQL驱动
func NewMySQLDatabase(config *Config) (Database, error) {
    // 实现MySQL数据库驱动
}

// 注册驱动
database.RegisterDriver("mysql", NewMySQLDatabase)
```

### 自定义DAO

```go
type CustomConfigDAO struct {
    dao.BaseDAO[RouterConfig]
}

func (d *CustomConfigDAO) FindByName(ctx context.Context, name string) (*RouterConfig, error) {
    return d.FindOneByCondition(ctx, map[string]interface{}{"name": name})
}

func NewCustomConfigDAO(manager dao.DAOManager) *CustomConfigDAO {
    return &CustomConfigDAO{
        BaseDAO: dao.CreateDAO[RouterConfig](manager),
    }
}
```

## 最佳实践

1. **使用全局管理器**: 对于单一数据库应用，使用全局数据库管理器
2. **合理使用事务**: 对于需要原子性的操作使用事务
3. **连接池配置**: 根据应用负载合理配置连接池参数
4. **错误处理**: 始终检查和处理数据库操作错误
5. **资源清理**: 确保在应用关闭时正确关闭数据库连接

## 注意事项

- 当前版本主要支持SQLite，其他数据库类型需要额外实现
- 批量更新操作在SQLite中通过事务实现，性能可能不如原生批量操作
- 使用泛型时需要Go 1.18+版本
- 数据库迁移需要手动调用，建议在应用启动时执行