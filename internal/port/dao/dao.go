package dao

import (
	"context"

	"router-os/internal/interfaces"
)

// PortConfigDAO 端口配置数据访问对象接口
type PortConfigDAO interface {
	// Create 创建端口配置
	Create(ctx context.Context, config *PortConfigModel) error

	// GetByInterfaceName 根据接口名称获取配置
	GetByInterfaceName(ctx context.Context, interfaceName string) (*PortConfigModel, error)

	// GetByRole 根据角色获取配置列表
	GetByRole(ctx context.Context, role interfaces.PortRole) ([]*PortConfigModel, error)

	// GetAll 获取所有配置
	GetAll(ctx context.Context) ([]*PortConfigModel, error)

	// GetEnabled 获取所有启用的配置
	GetEnabled(ctx context.Context) ([]*PortConfigModel, error)

	// Update 更新端口配置
	Update(ctx context.Context, config *PortConfigModel) error

	// UpdateRole 更新端口角色
	UpdateRole(ctx context.Context, interfaceName string, role interfaces.PortRole) error

	// UpdateEnabled 更新启用状态
	UpdateEnabled(ctx context.Context, interfaceName string, enabled bool) error

	// Delete 删除端口配置
	Delete(ctx context.Context, interfaceName string) error

	// DeleteByRole 删除指定角色的所有配置
	DeleteByRole(ctx context.Context, role interfaces.PortRole) error

	// Exists 检查配置是否存在
	Exists(ctx context.Context, interfaceName string) (bool, error)

	// Count 统计配置数量
	Count(ctx context.Context) (int64, error)

	// CountByRole 统计指定角色的配置数量
	CountByRole(ctx context.Context, role interfaces.PortRole) (int64, error)
}

// NetworkTopologyDAO 网络拓扑配置数据访问对象接口
type NetworkTopologyDAO interface {
	// Create 创建网络拓扑配置
	Create(ctx context.Context, topology *NetworkTopologyModel) error

	// GetByID 根据ID获取配置
	GetByID(ctx context.Context, id int64) (*NetworkTopologyModel, error)

	// GetByName 根据名称获取配置
	GetByName(ctx context.Context, name string) (*NetworkTopologyModel, error)

	// GetActive 获取当前活跃的配置
	GetActive(ctx context.Context) (*NetworkTopologyModel, error)

	// GetAll 获取所有配置
	GetAll(ctx context.Context) ([]*NetworkTopologyModel, error)

	// Update 更新网络拓扑配置
	Update(ctx context.Context, topology *NetworkTopologyModel) error

	// SetActive 设置活跃配置
	SetActive(ctx context.Context, id int64) error

	// Delete 删除网络拓扑配置
	Delete(ctx context.Context, id int64) error

	// Exists 检查配置是否存在
	Exists(ctx context.Context, name string) (bool, error)

	// Count 统计配置数量
	Count(ctx context.Context) (int64, error)
}

// PortRoleHistoryDAO 端口角色变更历史数据访问对象接口
type PortRoleHistoryDAO interface {
	// Create 创建历史记录
	Create(ctx context.Context, history *PortRoleHistoryModel) error

	// GetByInterfaceName 根据接口名称获取历史记录
	GetByInterfaceName(ctx context.Context, interfaceName string, limit int) ([]*PortRoleHistoryModel, error)

	// GetAll 获取所有历史记录
	GetAll(ctx context.Context, limit int) ([]*PortRoleHistoryModel, error)

	// GetByTimeRange 根据时间范围获取历史记录
	GetByTimeRange(ctx context.Context, startTime, endTime string, limit int) ([]*PortRoleHistoryModel, error)

	// Delete 删除历史记录
	Delete(ctx context.Context, id int64) error

	// DeleteOldRecords 删除旧记录（保留最近N天的记录）
	DeleteOldRecords(ctx context.Context, days int) error

	// Count 统计历史记录数量
	Count(ctx context.Context) (int64, error)
}
