package dao

import (
	"time"

	"router-os/internal/interfaces"
)

// PortConfig dao包独立的端口配置结构体
type PortConfig struct {
	InterfaceName string              `json:"interface_name"`
	Role          interfaces.PortRole `json:"role"`
	IPAddress     string              `json:"ip_address"`
	Netmask       string              `json:"netmask"`
	Gateway       string              `json:"gateway"`
	DHCPEnabled   bool                `json:"dhcp_enabled"`
	Description   string              `json:"description"`
}

// NetworkTopology dao包独立的网络拓扑结构体
type NetworkTopology struct {
	ID                  int64  `json:"id"`
	Name                string `json:"name"`
	NATEnabled          bool   `json:"nat_enabled"`
	IPForwardingEnabled bool   `json:"ip_forwarding_enabled"`
	Description         string `json:"description"`
	IsActive            bool   `json:"is_active"`
}

// PortConfigModel 端口配置数据模型
// 用于数据库存储的端口配置结构
type PortConfigModel struct {
	// ID 主键ID
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	// InterfaceName 接口名称
	InterfaceName string `json:"interface_name" gorm:"column:interface_name;type:varchar(50);not null;uniqueIndex"`

	// Role 端口角色 (0=unassigned, 1=wan, 2=lan, 3=dmz)
	Role int `json:"role" gorm:"column:role;type:int;not null;default:0"`

	// IPAddress IP地址
	IPAddress string `json:"ip_address" gorm:"column:ip_address;type:varchar(45)"`

	// Netmask 子网掩码
	Netmask string `json:"netmask" gorm:"column:netmask;type:varchar(45)"`

	// Gateway 网关地址
	Gateway string `json:"gateway" gorm:"column:gateway;type:varchar(45)"`

	// DHCPEnabled 是否启用DHCP
	DHCPEnabled bool `json:"dhcp_enabled" gorm:"column:dhcp_enabled;type:boolean;default:false"`

	// Description 端口描述
	Description string `json:"description" gorm:"column:description;type:text"`

	// Enabled 是否启用
	Enabled bool `json:"enabled" gorm:"column:enabled;type:boolean;default:true"`

	// CreatedAt 创建时间
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`

	// UpdatedAt 更新时间
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}

// TableName 指定表名
func (PortConfigModel) TableName() string {
	return "port_configs"
}

// ToPortConfig 转换为PortConfig结构
func (p *PortConfigModel) ToPortConfig() *PortConfig {
	return &PortConfig{
		InterfaceName: p.InterfaceName,
		Role:          interfaces.PortRole(p.Role),
		IPAddress:     p.IPAddress,
		Netmask:       p.Netmask,
		Gateway:       p.Gateway,
		DHCPEnabled:   p.DHCPEnabled,
		Description:   p.Description,
	}
}

// FromPortConfig 从PortConfig结构创建
func (p *PortConfigModel) FromPortConfig(config *PortConfig) {
	p.InterfaceName = config.InterfaceName
	p.Role = int(config.Role)
	p.IPAddress = config.IPAddress
	p.Netmask = config.Netmask
	p.Gateway = config.Gateway
	p.DHCPEnabled = config.DHCPEnabled
	p.Description = config.Description
	p.Enabled = true
}

// ToModel 将PortConfig转换为PortConfigModel
func ToPortConfigModel(config *PortConfig) *PortConfigModel {
	model := &PortConfigModel{}
	model.FromPortConfig(config)
	return model
}

// NetworkTopologyModel 网络拓扑配置数据模型
type NetworkTopologyModel struct {
	// ID 主键ID
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	// Name 配置名称
	Name string `json:"name" gorm:"column:name;type:varchar(100);not null"`

	// NATEnabled 是否启用NAT
	NATEnabled bool `json:"nat_enabled" gorm:"column:nat_enabled;type:boolean;default:true"`

	// IPForwardingEnabled 是否启用IP转发
	IPForwardingEnabled bool `json:"ip_forwarding_enabled" gorm:"column:ip_forwarding_enabled;type:boolean;default:true"`

	// Description 配置描述
	Description string `json:"description" gorm:"column:description;type:text"`

	// IsActive 是否为当前活跃配置
	IsActive bool `json:"is_active" gorm:"column:is_active;type:boolean;default:false"`

	// CreatedAt 创建时间
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`

	// UpdatedAt 更新时间
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}

// TableName 指定表名
func (NetworkTopologyModel) TableName() string {
	return "network_topologies"
}

// ToNetworkTopology 转换为NetworkTopology结构
func (n *NetworkTopologyModel) ToNetworkTopology() *NetworkTopology {
	return &NetworkTopology{
		ID:                  n.ID,
		Name:                n.Name,
		NATEnabled:          n.NATEnabled,
		IPForwardingEnabled: n.IPForwardingEnabled,
		Description:         n.Description,
		IsActive:            n.IsActive,
	}
}

// FromNetworkTopology 从NetworkTopology结构创建
func (n *NetworkTopologyModel) FromNetworkTopology(topology *NetworkTopology) {
	n.Name = topology.Name
	n.NATEnabled = topology.NATEnabled
	n.IPForwardingEnabled = topology.IPForwardingEnabled
	n.Description = topology.Description
}

// ToNetworkTopologyModel 将NetworkTopology转换为NetworkTopologyModel
func ToNetworkTopologyModel(topology *NetworkTopology) *NetworkTopologyModel {
	model := &NetworkTopologyModel{}
	model.FromNetworkTopology(topology)
	return model
}

// PortRoleHistoryModel 端口角色变更历史
type PortRoleHistoryModel struct {
	// ID 主键ID
	ID int64 `json:"id" gorm:"primaryKey;autoIncrement"`

	// InterfaceName 接口名称
	InterfaceName string `json:"interface_name" gorm:"column:interface_name;type:varchar(50);not null"`

	// OldRole 旧角色
	OldRole int `json:"old_role" gorm:"column:old_role;type:int"`

	// NewRole 新角色
	NewRole int `json:"new_role" gorm:"column:new_role;type:int"`

	// ChangeReason 变更原因
	ChangeReason string `json:"change_reason" gorm:"column:change_reason;type:varchar(255)"`

	// OperatorIP 操作者IP
	OperatorIP string `json:"operator_ip" gorm:"column:operator_ip;type:varchar(45)"`

	// CreatedAt 创建时间
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
}

// TableName 指定表名
func (PortRoleHistoryModel) TableName() string {
	return "port_role_histories"
}
