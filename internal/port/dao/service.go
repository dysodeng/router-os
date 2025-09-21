package dao

import (
	"context"
	"fmt"
	"time"

	"router-os/internal/database"
	"router-os/internal/interfaces"
)

// PortService 端口管理服务
type PortService struct {
	portConfigDAO      PortConfigDAO
	networkTopologyDAO NetworkTopologyDAO
	portRoleHistoryDAO PortRoleHistoryDAO
	db                 database.Database
}

// NewPortService 创建端口管理服务实例
func NewPortService(db database.Database) *PortService {
	return &PortService{
		portConfigDAO:      NewPortConfigDAO(db),
		networkTopologyDAO: NewNetworkTopologyDAO(db),
		portRoleHistoryDAO: NewPortRoleHistoryDAO(db),
		db:                 db,
	}
}

// InitializeTables 初始化数据库表
func (s *PortService) InitializeTables() error {
	return s.db.Migrate(
		&PortConfigModel{},
		&NetworkTopologyModel{},
		&PortRoleHistoryModel{},
	)
}

// CreatePortConfig 创建端口配置
func (s *PortService) CreatePortConfig(ctx context.Context, config *PortConfig) error {
	// 检查接口名称是否已存在
	exists, err := s.portConfigDAO.Exists(ctx, config.InterfaceName)
	if err != nil {
		return fmt.Errorf("检查端口配置是否存在失败: %w", err)
	}
	if exists {
		return fmt.Errorf("接口 %s 的配置已存在", config.InterfaceName)
	}

	// 转换为数据模型
	model := ToPortConfigModel(config)

	// 创建配置
	if err = s.portConfigDAO.Create(ctx, model); err != nil {
		return fmt.Errorf("创建端口配置失败: %w", err)
	}

	// 记录角色变更历史
	history := &PortRoleHistoryModel{
		InterfaceName: config.InterfaceName,
		OldRole:       int(interfaces.PortRoleUnassigned), // 新创建的端口，旧角色为未分配
		NewRole:       int(config.Role),
		ChangeReason:  "创建端口配置",
		CreatedAt:     time.Now(),
	}

	if err = s.portRoleHistoryDAO.Create(ctx, history); err != nil {
		// 历史记录失败不影响主要操作，只记录日志
		// 在实际项目中应该使用日志库
		fmt.Printf("记录端口角色变更历史失败: %v\n", err)
	}

	return nil
}

// GetPortConfig 获取端口配置
func (s *PortService) GetPortConfig(ctx context.Context, interfaceName string) (*PortConfig, error) {
	model, err := s.portConfigDAO.GetByInterfaceName(ctx, interfaceName)
	if err != nil {
		return nil, fmt.Errorf("获取端口配置失败: %w", err)
	}
	return model.ToPortConfig(), nil
}

// GetPortConfigsByRole 根据角色获取端口配置列表
func (s *PortService) GetPortConfigsByRole(ctx context.Context, role interfaces.PortRole) ([]*PortConfig, error) {
	models, err := s.portConfigDAO.GetByRole(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("根据角色获取端口配置失败: %w", err)
	}

	configs := make([]*PortConfig, len(models))
	for i, model := range models {
		configs[i] = model.ToPortConfig()
	}
	return configs, nil
}

// GetAllPortConfigs 获取所有端口配置
func (s *PortService) GetAllPortConfigs(ctx context.Context) ([]*PortConfig, error) {
	models, err := s.portConfigDAO.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取所有端口配置失败: %w", err)
	}

	configs := make([]*PortConfig, len(models))
	for i, model := range models {
		configs[i] = model.ToPortConfig()
	}
	return configs, nil
}

// GetEnabledPortConfigs 获取所有启用的端口配置
func (s *PortService) GetEnabledPortConfigs(ctx context.Context) ([]*PortConfig, error) {
	models, err := s.portConfigDAO.GetEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取启用的端口配置失败: %w", err)
	}

	configs := make([]*PortConfig, len(models))
	for i, model := range models {
		configs[i] = model.ToPortConfig()
	}
	return configs, nil
}

// UpdatePortConfig 更新端口配置
func (s *PortService) UpdatePortConfig(ctx context.Context, config *PortConfig) error {
	// 获取旧配置用于记录历史
	oldModel, err := s.portConfigDAO.GetByInterfaceName(ctx, config.InterfaceName)
	if err != nil {
		return fmt.Errorf("获取旧端口配置失败: %w", err)
	}

	// 转换为数据模型
	model := ToPortConfigModel(config)

	// 更新配置
	if err = s.portConfigDAO.Update(ctx, model); err != nil {
		return fmt.Errorf("更新端口配置失败: %w", err)
	}

	// 如果角色发生变化，记录历史
	if oldModel.Role != model.Role {
		history := &PortRoleHistoryModel{
			InterfaceName: config.InterfaceName,
			OldRole:       oldModel.Role,
			NewRole:       model.Role,
			ChangeReason:  "更新端口配置",
			CreatedAt:     time.Now(),
		}

		if err = s.portRoleHistoryDAO.Create(ctx, history); err != nil {
			fmt.Printf("记录端口角色变更历史失败: %v\n", err)
		}
	}

	return nil
}

// UpdatePortRole 更新端口角色
func (s *PortService) UpdatePortRole(ctx context.Context, interfaceName string, role interfaces.PortRole, reason string) error {
	// 获取旧配置
	oldModel, err := s.portConfigDAO.GetByInterfaceName(ctx, interfaceName)
	if err != nil {
		return fmt.Errorf("获取端口配置失败: %w", err)
	}

	oldRole := interfaces.PortRole(oldModel.Role)

	// 如果角色没有变化，直接返回
	if oldRole == role {
		return nil
	}

	// 更新角色
	if err = s.portConfigDAO.UpdateRole(ctx, interfaceName, role); err != nil {
		return fmt.Errorf("更新端口角色失败: %w", err)
	}

	// 记录角色变更历史
	history := &PortRoleHistoryModel{
		InterfaceName: interfaceName,
		OldRole:       int(oldRole),
		NewRole:       int(role),
		ChangeReason:  reason,
		CreatedAt:     time.Now(),
	}

	if err = s.portRoleHistoryDAO.Create(ctx, history); err != nil {
		fmt.Printf("记录端口角色变更历史失败: %v\n", err)
	}

	return nil
}

// UpdatePortEnabled 更新端口启用状态
func (s *PortService) UpdatePortEnabled(ctx context.Context, interfaceName string, enabled bool) error {
	if err := s.portConfigDAO.UpdateEnabled(ctx, interfaceName, enabled); err != nil {
		return fmt.Errorf("更新端口启用状态失败: %w", err)
	}
	return nil
}

// DeletePortConfig 删除端口配置
func (s *PortService) DeletePortConfig(ctx context.Context, interfaceName string) error {
	// 获取配置用于记录历史
	model, err := s.portConfigDAO.GetByInterfaceName(ctx, interfaceName)
	if err != nil {
		return fmt.Errorf("获取端口配置失败: %w", err)
	}

	// 删除配置
	if err = s.portConfigDAO.Delete(ctx, interfaceName); err != nil {
		return fmt.Errorf("删除端口配置失败: %w", err)
	}

	// 记录角色变更历史
	history := &PortRoleHistoryModel{
		InterfaceName: interfaceName,
		OldRole:       model.Role,
		NewRole:       int(interfaces.PortRoleUnassigned),
		ChangeReason:  "删除端口配置",
		CreatedAt:     time.Now(),
	}

	if err = s.portRoleHistoryDAO.Create(ctx, history); err != nil {
		fmt.Printf("记录端口角色变更历史失败: %v\n", err)
	}

	return nil
}

// GetPortRoleHistory 获取端口角色变更历史
func (s *PortService) GetPortRoleHistory(ctx context.Context, interfaceName string, limit int) ([]*PortRoleHistoryModel, error) {
	return s.portRoleHistoryDAO.GetByInterfaceName(ctx, interfaceName, limit)
}

// GetAllPortRoleHistory 获取所有端口角色变更历史
func (s *PortService) GetAllPortRoleHistory(ctx context.Context, limit int) ([]*PortRoleHistoryModel, error) {
	return s.portRoleHistoryDAO.GetAll(ctx, limit)
}

// CreateNetworkTopology 创建网络拓扑配置
func (s *PortService) CreateNetworkTopology(ctx context.Context, name string, topology *NetworkTopology) error {
	// 检查名称是否已存在
	exists, err := s.networkTopologyDAO.Exists(ctx, name)
	if err != nil {
		return fmt.Errorf("检查网络拓扑配置是否存在失败: %w", err)
	}
	if exists {
		return fmt.Errorf("网络拓扑配置 %s 已存在", name)
	}

	// 转换为数据模型
	model := ToNetworkTopologyModel(topology)
	model.Name = name

	// 创建配置
	if err = s.networkTopologyDAO.Create(ctx, model); err != nil {
		return fmt.Errorf("创建网络拓扑配置失败: %w", err)
	}

	return nil
}

// GetNetworkTopology 获取网络拓扑配置
func (s *PortService) GetNetworkTopology(ctx context.Context, name string) (*NetworkTopology, error) {
	model, err := s.networkTopologyDAO.GetByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("获取网络拓扑配置失败: %w", err)
	}
	return model.ToNetworkTopology(), nil
}

// GetActiveNetworkTopology 获取当前活跃的网络拓扑配置
func (s *PortService) GetActiveNetworkTopology(ctx context.Context) (*NetworkTopology, error) {
	model, err := s.networkTopologyDAO.GetActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取活跃网络拓扑配置失败: %w", err)
	}
	return model.ToNetworkTopology(), nil
}

// GetAllNetworkTopologies 获取所有网络拓扑配置
func (s *PortService) GetAllNetworkTopologies(ctx context.Context) ([]*NetworkTopology, error) {
	models, err := s.networkTopologyDAO.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取所有网络拓扑配置失败: %w", err)
	}

	topologies := make([]*NetworkTopology, len(models))
	for i, model := range models {
		topologies[i] = model.ToNetworkTopology()
	}
	return topologies, nil
}

// SetActiveNetworkTopology 设置活跃的网络拓扑配置
func (s *PortService) SetActiveNetworkTopology(ctx context.Context, id int64) error {
	if err := s.networkTopologyDAO.SetActive(ctx, id); err != nil {
		return fmt.Errorf("设置活跃网络拓扑配置失败: %w", err)
	}
	return nil
}

// UpdateNetworkTopology 更新网络拓扑配置
func (s *PortService) UpdateNetworkTopology(ctx context.Context, topology *NetworkTopology) error {
	model := ToNetworkTopologyModel(topology)
	if err := s.networkTopologyDAO.Update(ctx, model); err != nil {
		return fmt.Errorf("更新网络拓扑配置失败: %w", err)
	}
	return nil
}

// DeleteNetworkTopology 删除网络拓扑配置
func (s *PortService) DeleteNetworkTopology(ctx context.Context, id int64) error {
	if err := s.networkTopologyDAO.Delete(ctx, id); err != nil {
		return fmt.Errorf("删除网络拓扑配置失败: %w", err)
	}
	return nil
}

// GetPortConfigStats 获取端口配置统计信息
func (s *PortService) GetPortConfigStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// 总配置数量
	totalCount, err := s.portConfigDAO.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取总配置数量失败: %w", err)
	}
	stats["total"] = totalCount

	// 各角色配置数量
	roleStats := make(map[string]int64)
	roles := []interfaces.PortRole{
		interfaces.PortRoleUnassigned,
		interfaces.PortRoleWAN,
		interfaces.PortRoleLAN,
		interfaces.PortRoleDMZ,
	}

	for _, role := range roles {
		count, err := s.portConfigDAO.CountByRole(ctx, role)
		if err != nil {
			return nil, fmt.Errorf("获取角色 %s 配置数量失败: %w", role.String(), err)
		}
		roleStats[role.String()] = count
	}
	stats["by_role"] = roleStats

	// 网络拓扑配置数量
	topologyCount, err := s.networkTopologyDAO.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取网络拓扑配置数量失败: %w", err)
	}
	stats["topology_count"] = topologyCount

	// 历史记录数量
	historyCount, err := s.portRoleHistoryDAO.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取历史记录数量失败: %w", err)
	}
	stats["history_count"] = historyCount

	return stats, nil
}

// CleanupOldHistory 清理旧的历史记录
func (s *PortService) CleanupOldHistory(ctx context.Context, days int) error {
	if err := s.portRoleHistoryDAO.DeleteOldRecords(ctx, days); err != nil {
		return fmt.Errorf("清理旧历史记录失败: %w", err)
	}
	return nil
}
