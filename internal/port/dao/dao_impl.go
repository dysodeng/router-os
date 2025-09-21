package dao

import (
	"context"
	"fmt"
	"time"

	"router-os/internal/database"
	"router-os/internal/interfaces"
)

// PortConfigDAOImpl 端口配置DAO的实现
type PortConfigDAOImpl struct {
	db database.Database
}

// NewPortConfigDAO 创建端口配置DAO实例
func NewPortConfigDAO(db database.Database) PortConfigDAO {
	return &PortConfigDAOImpl{
		db: db,
	}
}

// Create 创建端口配置
func (d *PortConfigDAOImpl) Create(ctx context.Context, config *PortConfigModel) error {
	return d.db.Create(ctx, config)
}

// GetByInterfaceName 根据接口名称获取配置
func (d *PortConfigDAOImpl) GetByInterfaceName(ctx context.Context, interfaceName string) (*PortConfigModel, error) {
	var config PortConfigModel
	condition := map[string]interface{}{"interface_name": interfaceName}
	err := d.db.FindOne(ctx, condition, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// GetByRole 根据角色获取配置列表
func (d *PortConfigDAOImpl) GetByRole(ctx context.Context, role interfaces.PortRole) ([]*PortConfigModel, error) {
	var configs []*PortConfigModel
	condition := map[string]interface{}{"role": int(role)}
	err := d.db.FindAll(ctx, condition, &configs)
	return configs, err
}

// GetAll 获取所有配置
func (d *PortConfigDAOImpl) GetAll(ctx context.Context) ([]*PortConfigModel, error) {
	var configs []*PortConfigModel
	err := d.db.FindAll(ctx, nil, &configs)
	return configs, err
}

// GetEnabled 获取所有启用的配置
func (d *PortConfigDAOImpl) GetEnabled(ctx context.Context) ([]*PortConfigModel, error) {
	var configs []*PortConfigModel
	condition := map[string]interface{}{"enabled": true}
	err := d.db.FindAll(ctx, condition, &configs)
	return configs, err
}

// Update 更新端口配置
func (d *PortConfigDAOImpl) Update(ctx context.Context, config *PortConfigModel) error {
	return d.db.Update(ctx, config)
}

// UpdateRole 更新端口角色
func (d *PortConfigDAOImpl) UpdateRole(ctx context.Context, interfaceName string, role interfaces.PortRole) error {
	// 先获取现有配置
	config, err := d.GetByInterfaceName(ctx, interfaceName)
	if err != nil {
		return err
	}
	// 更新角色
	config.Role = int(role)
	return d.db.Update(ctx, config)
}

// UpdateEnabled 更新启用状态
func (d *PortConfigDAOImpl) UpdateEnabled(ctx context.Context, interfaceName string, enabled bool) error {
	// 先获取现有配置
	config, err := d.GetByInterfaceName(ctx, interfaceName)
	if err != nil {
		return err
	}
	// 更新启用状态
	config.Enabled = enabled
	return d.db.Update(ctx, config)
}

// Delete 删除端口配置
func (d *PortConfigDAOImpl) Delete(ctx context.Context, interfaceName string) error {
	config, err := d.GetByInterfaceName(ctx, interfaceName)
	if err != nil {
		return err
	}
	return d.db.Delete(ctx, config)
}

// DeleteByRole 删除指定角色的所有配置
func (d *PortConfigDAOImpl) DeleteByRole(ctx context.Context, role interfaces.PortRole) error {
	configs, err := d.GetByRole(ctx, role)
	if err != nil {
		return err
	}
	for _, config := range configs {
		if err = d.db.Delete(ctx, config); err != nil {
			return err
		}
	}
	return nil
}

// Exists 检查配置是否存在
func (d *PortConfigDAOImpl) Exists(ctx context.Context, interfaceName string) (bool, error) {
	condition := map[string]interface{}{"interface_name": interfaceName}
	return d.db.Exists(ctx, condition, &PortConfigModel{})
}

// Count 统计配置数量
func (d *PortConfigDAOImpl) Count(ctx context.Context) (int64, error) {
	return d.db.Count(ctx, nil, &PortConfigModel{})
}

// CountByRole 统计指定角色的配置数量
func (d *PortConfigDAOImpl) CountByRole(ctx context.Context, role interfaces.PortRole) (int64, error) {
	condition := map[string]interface{}{"role": int(role)}
	return d.db.Count(ctx, condition, &PortConfigModel{})
}

// NetworkTopologyDAOImpl 网络拓扑配置DAO的实现
type NetworkTopologyDAOImpl struct {
	db database.Database
}

// NewNetworkTopologyDAO 创建网络拓扑配置DAO实例
func NewNetworkTopologyDAO(db database.Database) NetworkTopologyDAO {
	return &NetworkTopologyDAOImpl{
		db: db,
	}
}

// Create 创建网络拓扑配置
func (d *NetworkTopologyDAOImpl) Create(ctx context.Context, topology *NetworkTopologyModel) error {
	return d.db.Create(ctx, topology)
}

// GetByID 根据ID获取配置
func (d *NetworkTopologyDAOImpl) GetByID(ctx context.Context, id int64) (*NetworkTopologyModel, error) {
	var topology NetworkTopologyModel
	err := d.db.FindByID(ctx, id, &topology)
	if err != nil {
		return nil, err
	}
	return &topology, nil
}

// GetByName 根据名称获取配置
func (d *NetworkTopologyDAOImpl) GetByName(ctx context.Context, name string) (*NetworkTopologyModel, error) {
	var topology NetworkTopologyModel
	condition := map[string]interface{}{"name": name}
	err := d.db.FindOne(ctx, condition, &topology)
	if err != nil {
		return nil, err
	}
	return &topology, nil
}

// GetActive 获取当前活跃的配置
func (d *NetworkTopologyDAOImpl) GetActive(ctx context.Context) (*NetworkTopologyModel, error) {
	var topology NetworkTopologyModel
	condition := map[string]interface{}{"is_active": true}
	err := d.db.FindOne(ctx, condition, &topology)
	if err != nil {
		return nil, err
	}
	return &topology, nil
}

// GetAll 获取所有配置
func (d *NetworkTopologyDAOImpl) GetAll(ctx context.Context) ([]*NetworkTopologyModel, error) {
	var topologies []*NetworkTopologyModel
	err := d.db.FindAll(ctx, nil, &topologies)
	return topologies, err
}

// Update 更新网络拓扑配置
func (d *NetworkTopologyDAOImpl) Update(ctx context.Context, topology *NetworkTopologyModel) error {
	return d.db.Update(ctx, topology)
}

// SetActive 设置活跃配置
func (d *NetworkTopologyDAOImpl) SetActive(ctx context.Context, id int64) error {
	// 使用事务确保原子性
	tx, err := d.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			_ = tx.Commit()
		}
	}()

	// 先将所有配置设为非活跃
	allTopologies, err := d.GetAll(ctx)
	if err != nil {
		return err
	}
	for _, topology := range allTopologies {
		topology.IsActive = false
		if err = tx.Update(ctx, topology); err != nil {
			return err
		}
	}

	// 再将指定配置设为活跃
	targetTopology, err := d.GetByID(ctx, id)
	if err != nil {
		return err
	}
	targetTopology.IsActive = true
	return tx.Update(ctx, targetTopology)
}

// Delete 删除网络拓扑配置
func (d *NetworkTopologyDAOImpl) Delete(ctx context.Context, id int64) error {
	topology, err := d.GetByID(ctx, id)
	if err != nil {
		return err
	}
	return d.db.Delete(ctx, topology)
}

// Exists 检查配置是否存在
func (d *NetworkTopologyDAOImpl) Exists(ctx context.Context, name string) (bool, error) {
	condition := map[string]interface{}{"name": name}
	return d.db.Exists(ctx, condition, &NetworkTopologyModel{})
}

// Count 统计配置数量
func (d *NetworkTopologyDAOImpl) Count(ctx context.Context) (int64, error) {
	return d.db.Count(ctx, nil, &NetworkTopologyModel{})
}

// PortRoleHistoryDAOImpl 端口角色变更历史DAO的实现
type PortRoleHistoryDAOImpl struct {
	db database.Database
}

// NewPortRoleHistoryDAO 创建端口角色变更历史DAO实例
func NewPortRoleHistoryDAO(db database.Database) PortRoleHistoryDAO {
	return &PortRoleHistoryDAOImpl{
		db: db,
	}
}

// Create 创建历史记录
func (d *PortRoleHistoryDAOImpl) Create(ctx context.Context, history *PortRoleHistoryModel) error {
	return d.db.Create(ctx, history)
}

// GetByInterfaceName 根据接口名称获取历史记录
func (d *PortRoleHistoryDAOImpl) GetByInterfaceName(ctx context.Context, interfaceName string, limit int) ([]*PortRoleHistoryModel, error) {
	var histories []*PortRoleHistoryModel
	condition := map[string]interface{}{"interface_name": interfaceName}
	orderBy := "created_at DESC"

	if limit > 0 {
		// 使用分页查询并排序
		_, err := d.db.FindWithPaginationAndOrder(ctx, condition, &histories, 0, limit, orderBy)
		return histories, err
	} else {
		// 如果没有限制，使用排序查询
		err := d.db.FindAllWithOrder(ctx, condition, &histories, orderBy)
		return histories, err
	}
}

// GetAll 获取所有历史记录
func (d *PortRoleHistoryDAOImpl) GetAll(ctx context.Context, limit int) ([]*PortRoleHistoryModel, error) {
	var histories []*PortRoleHistoryModel
	orderBy := "created_at DESC"

	if limit > 0 {
		// 使用分页查询并排序
		_, err := d.db.FindWithPaginationAndOrder(ctx, nil, &histories, 0, limit, orderBy)
		return histories, err
	} else {
		// 如果没有限制，使用排序查询
		err := d.db.FindAllWithOrder(ctx, nil, &histories, orderBy)
		return histories, err
	}
}

// GetByTimeRange 根据时间范围获取历史记录
func (d *PortRoleHistoryDAOImpl) GetByTimeRange(ctx context.Context, startTime, endTime string, limit int) ([]*PortRoleHistoryModel, error) {
	var histories []*PortRoleHistoryModel

	// 解析时间字符串
	startTimeObj, err := time.Parse(time.RFC3339, startTime)
	if err != nil {
		return nil, fmt.Errorf("invalid start time format: %v", err)
	}

	endTimeObj, err := time.Parse(time.RFC3339, endTime)
	if err != nil {
		return nil, fmt.Errorf("invalid end time format: %v", err)
	}

	// 构建查询条件 - 使用GORM的条件格式
	condition := "created_at >= ? AND created_at <= ?"
	args := []interface{}{startTimeObj, endTimeObj}
	orderBy := "created_at DESC"

	if limit > 0 {
		// 使用分页查询并排序
		_, err := d.db.FindWithConditionPaginationAndOrder(ctx, condition, args, &histories, 0, limit, orderBy)
		return histories, err
	} else {
		// 如果没有限制，使用排序查询
		err := d.db.FindAllWithConditionAndOrder(ctx, condition, args, &histories, orderBy)
		return histories, err
	}
}

// Delete 删除历史记录
func (d *PortRoleHistoryDAOImpl) Delete(ctx context.Context, id int64) error {
	var history PortRoleHistoryModel
	err := d.db.FindByID(ctx, id, &history)
	if err != nil {
		return err
	}
	return d.db.Delete(ctx, &history)
}

// DeleteOldRecords 删除旧记录（保留最近N天的记录）
func (d *PortRoleHistoryDAOImpl) DeleteOldRecords(ctx context.Context, days int) error {
	cutoffTime := time.Now().AddDate(0, 0, -days)
	sql := "DELETE FROM port_role_histories WHERE created_at < ?"
	return d.db.Exec(ctx, sql, cutoffTime)
}

// Count 统计历史记录数量
func (d *PortRoleHistoryDAOImpl) Count(ctx context.Context) (int64, error) {
	return d.db.Count(ctx, nil, &PortRoleHistoryModel{})
}
