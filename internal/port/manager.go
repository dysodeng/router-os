package port

import (
	"fmt"
	"log"
	"net"
	"sync"

	"router-os/internal/interfaces"
)

// Manager 端口管理器
// 负责网络接口的角色分配、NAT规则管理和路由配置
// 这是路由器核心功能的管理组件
//
// 主要功能：
// 1. WAN/LAN端口角色分配和管理
// 2. 自动配置NAT转发规则
// 3. 接口配置的统一管理
// 4. 网络拓扑的动态调整
//
// 设计特点：
// - 与接口管理器协同工作
// - 自动化NAT规则配置
// - 支持多WAN和多LAN配置
// - 提供配置验证和冲突检测
type Manager struct {
	// interfaceManager 接口管理器引用
	// 用于获取和操作网络接口信息
	interfaceManager *interfaces.Manager

	// natManager NAT管理器引用
	// 用于配置和管理NAT转发规则
	natManager NATManager

	// mu 读写互斥锁
	// 保护端口配置的并发访问
	mu sync.RWMutex

	// running 管理器运行状态
	// 标识端口管理器是否处于活跃状态
	running bool
}

// NATManager NAT管理接口
// 定义NAT规则管理的标准接口，支持不同的NAT实现
type NATManager interface {
	// AddMasqueradeRule 添加MASQUERADE规则
	// 为指定的WAN接口添加源地址转换规则
	AddMasqueradeRule(wanInterface string, lanNetwork string) error

	// RemoveMasqueradeRule 移除MASQUERADE规则
	// 删除指定WAN接口的源地址转换规则
	RemoveMasqueradeRule(wanInterface string, lanNetwork string) error

	// AddForwardRule 添加转发规则
	// 配置接口间的数据包转发规则
	AddForwardRule(fromInterface, toInterface string) error

	// RemoveForwardRule 移除转发规则
	// 删除接口间的数据包转发规则
	RemoveForwardRule(fromInterface, toInterface string) error

	// EnableIPForwarding 启用IP转发
	// 在系统级别启用IP数据包转发功能
	EnableIPForwarding() error

	// DisableIPForwarding 禁用IP转发
	// 在系统级别禁用IP数据包转发功能
	DisableIPForwarding() error
}

// PortConfig 端口配置结构
// 定义单个端口的完整配置信息
type PortConfig struct {
	// InterfaceName 接口名称
	InterfaceName string `json:"interface_name"`

	// Role 端口角色
	Role interfaces.PortRole `json:"role"`

	// IPAddress IP地址（可选，用于静态配置）
	IPAddress string `json:"ip_address,omitempty"`

	// Netmask 子网掩码（可选）
	Netmask string `json:"netmask,omitempty"`

	// Gateway 网关地址（可选，主要用于WAN接口）
	Gateway string `json:"gateway,omitempty"`

	// DHCPEnabled 是否启用DHCP（主要用于LAN接口）
	DHCPEnabled bool `json:"dhcp_enabled"`

	// Description 端口描述
	Description string `json:"description,omitempty"`
}

// NetworkTopology 网络拓扑配置
// 定义整个网络的拓扑结构和配置
type NetworkTopology struct {
	// WANPorts WAN端口配置列表
	WANPorts []PortConfig `json:"wan_ports"`

	// LANPorts LAN端口配置列表
	LANPorts []PortConfig `json:"lan_ports"`

	// DMZPorts DMZ端口配置列表（可选）
	DMZPorts []PortConfig `json:"dmz_ports,omitempty"`

	// NATEnabled 是否启用NAT转发
	NATEnabled bool `json:"nat_enabled"`

	// IPForwardingEnabled 是否启用IP转发
	IPForwardingEnabled bool `json:"ip_forwarding_enabled"`
}

// NewManager 创建新的端口管理器
// 初始化端口管理器，关联接口管理器和NAT管理器
//
// 参数：
//   - interfaceManager: 接口管理器实例
//   - natManager: NAT管理器实例
//
// 返回值：
//   - *Manager: 初始化完成的端口管理器
//
// 使用示例：
//
//	ifaceManager := interfaces.NewManager()
//	natManager := nat.NewIptablesManager()
//	portManager := NewManager(ifaceManager, natManager)
func NewManager(interfaceManager *interfaces.Manager, natManager NATManager) *Manager {
	return &Manager{
		interfaceManager: interfaceManager,
		natManager:       natManager,
		running:          false,
	}
}

// Start 启动端口管理器
// 初始化端口管理器并开始监控接口状态
//
// 返回值：
//   - error: 启动失败时返回错误信息
//
// 启动过程：
// 1. 检查依赖组件状态
// 2. 启用IP转发功能
// 3. 应用当前端口配置
// 4. 设置运行状态
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("端口管理器已经在运行")
	}

	// 检查接口管理器状态
	if !m.interfaceManager.IsRunning() {
		return fmt.Errorf("接口管理器未运行，请先启动接口管理器")
	}

	// 启用IP转发
	if err := m.natManager.EnableIPForwarding(); err != nil {
		return fmt.Errorf("启用IP转发失败: %v", err)
	}

	m.running = true
	log.Println("端口管理器启动成功")
	return nil
}

// Stop 停止端口管理器
// 清理NAT规则并停止端口管理服务
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	// 这里可以添加清理NAT规则的逻辑
	// 但通常保留规则以维持网络连接

	m.running = false
	log.Println("端口管理器已停止")
}

// AssignPortRole 分配端口角色
// 为指定接口分配网络角色并应用相应配置
//
// 参数：
//   - interfaceName: 接口名称
//   - role: 要分配的端口角色
//
// 返回值：
//   - error: 分配失败时返回错误信息
//
// 功能：
// 1. 验证接口存在性
// 2. 设置接口角色
// 3. 应用角色相关的网络配置
// 4. 更新NAT规则（如果需要）
func (m *Manager) AssignPortRole(interfaceName string, role interfaces.PortRole) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return fmt.Errorf("端口管理器未运行")
	}

	// 检查接口是否存在
	iface, err := m.interfaceManager.GetInterface(interfaceName)
	if err != nil {
		return fmt.Errorf("接口 %s 不存在: %v", interfaceName, err)
	}

	// 获取当前角色，如果角色发生变化，需要清除旧的规则
	currentRole := iface.Role
	if currentRole != role {
		// 清除旧角色的规则
		if err := m.cleanupRoleRules(interfaceName, currentRole); err != nil {
			log.Printf("清除接口 %s 旧角色 %s 的规则时出错: %v", interfaceName, currentRole.String(), err)
			// 不返回错误，继续设置新角色
		}
	}

	// 设置接口角色
	if err := m.interfaceManager.SetInterfaceRole(interfaceName, role); err != nil {
		return fmt.Errorf("设置接口角色失败: %v", err)
	}

	// 根据角色应用相应配置
	switch role {
	case interfaces.PortRoleWAN:
		if err := m.configureWANInterface(interfaceName); err != nil {
			return fmt.Errorf("配置WAN接口失败: %v", err)
		}
	case interfaces.PortRoleLAN:
		if err := m.configureLANInterface(interfaceName); err != nil {
			return fmt.Errorf("配置LAN接口失败: %v", err)
		}
	case interfaces.PortRoleDMZ:
		if err := m.configureDMZInterface(interfaceName); err != nil {
			return fmt.Errorf("配置DMZ接口失败: %v", err)
		}
	case interfaces.PortRoleUnassigned:
		log.Printf("接口 %s 设置为未分配角色，已清除相关规则", interfaceName)
	}

	log.Printf("成功为接口 %s 分配角色: %s", interfaceName, role.String())
	return nil
}

// configureWANInterface 配置WAN接口
// 为WAN接口应用特定的网络配置和NAT规则
func (m *Manager) configureWANInterface(interfaceName string) error {
	// 获取所有LAN接口，为它们配置NAT规则
	lanInterfaces := m.interfaceManager.GetLANInterfaces()

	for _, lanIface := range lanInterfaces {
		if lanIface.IPAddress != nil && lanIface.Netmask != nil {
			// 正确计算网络地址和CIDR前缀
			lanNetwork := m.calculateNetworkCIDR(lanIface.IPAddress, lanIface.Netmask)

			// 添加MASQUERADE规则
			if err := m.natManager.AddMasqueradeRule(interfaceName, lanNetwork); err != nil {
				log.Printf("警告: 为WAN接口 %s 添加NAT规则失败: %v", interfaceName, err)
			}
		}

		// 添加转发规则
		if err := m.natManager.AddForwardRule(lanIface.Name, interfaceName); err != nil {
			log.Printf("警告: 添加转发规则失败 (%s -> %s): %v",
				lanIface.Name, interfaceName, err)
		}
	}

	return nil
}

// configureLANInterface 配置LAN接口
// 为LAN接口应用特定的网络配置
func (m *Manager) configureLANInterface(interfaceName string) error {
	// 获取所有WAN接口，为它们配置NAT规则
	wanInterfaces := m.interfaceManager.GetWANInterfaces()

	// 获取当前LAN接口信息
	lanIface, err := m.interfaceManager.GetInterface(interfaceName)
	if err != nil {
		return err
	}

	if lanIface.IPAddress != nil && lanIface.Netmask != nil {
		// 正确计算网络地址和CIDR前缀
		lanNetwork := m.calculateNetworkCIDR(lanIface.IPAddress, lanIface.Netmask)

		for _, wanIface := range wanInterfaces {
			// 添加MASQUERADE规则
			if err := m.natManager.AddMasqueradeRule(wanIface.Name, lanNetwork); err != nil {
				log.Printf("警告: 为LAN接口 %s 添加NAT规则失败: %v", interfaceName, err)
			}

			// 添加转发规则
			if err := m.natManager.AddForwardRule(interfaceName, wanIface.Name); err != nil {
				log.Printf("警告: 添加转发规则失败 (%s -> %s): %v",
					interfaceName, wanIface.Name, err)
			}
		}
	}

	return nil
}

// configureDMZInterface 配置DMZ接口
// 为DMZ接口应用特定的网络配置和安全策略
func (m *Manager) configureDMZInterface(interfaceName string) error {
	// DMZ接口的配置逻辑
	// 通常需要特殊的防火墙规则和访问控制
	log.Printf("配置DMZ接口: %s", interfaceName)
	return nil
}

// GetNetworkTopology 获取当前网络拓扑
// 返回当前系统的完整网络拓扑配置
//
// 返回值：
//   - *NetworkTopology: 网络拓扑配置
//   - error: 获取失败时返回错误信息
func (m *Manager) GetNetworkTopology() (*NetworkTopology, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	topology := &NetworkTopology{
		NATEnabled:          true,
		IPForwardingEnabled: true,
	}

	// 获取WAN端口
	wanInterfaces := m.interfaceManager.GetWANInterfaces()
	for _, iface := range wanInterfaces {
		config := PortConfig{
			InterfaceName: iface.Name,
			Role:          iface.Role,
		}
		if iface.IPAddress != nil {
			config.IPAddress = iface.IPAddress.String()
		}
		if iface.Netmask != nil {
			config.Netmask = iface.Netmask.String()
		}
		if iface.Gateway != nil {
			config.Gateway = iface.Gateway.String()
		}
		topology.WANPorts = append(topology.WANPorts, config)
	}

	// 获取LAN端口
	lanInterfaces := m.interfaceManager.GetLANInterfaces()
	for _, iface := range lanInterfaces {
		config := PortConfig{
			InterfaceName: iface.Name,
			Role:          iface.Role,
			DHCPEnabled:   true, // 假设LAN接口启用DHCP
		}
		if iface.IPAddress != nil {
			config.IPAddress = iface.IPAddress.String()
		}
		if iface.Netmask != nil {
			config.Netmask = iface.Netmask.String()
		}
		topology.LANPorts = append(topology.LANPorts, config)
	}

	// 获取DMZ端口
	dmzInterfaces := m.interfaceManager.GetInterfacesByRole(interfaces.PortRoleDMZ)
	for _, iface := range dmzInterfaces {
		config := PortConfig{
			InterfaceName: iface.Name,
			Role:          iface.Role,
		}
		if iface.IPAddress != nil {
			config.IPAddress = iface.IPAddress.String()
		}
		if iface.Netmask != nil {
			config.Netmask = iface.Netmask.String()
		}
		topology.DMZPorts = append(topology.DMZPorts, config)
	}

	return topology, nil
}

// IsRunning 检查端口管理器是否正在运行
// 返回管理器的当前运行状态
//
// 返回值：
//   - bool: true表示正在运行，false表示已停止
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// calculateNetworkCIDR 计算网络地址的CIDR表示法
// 根据IP地址和子网掩码计算正确的网络地址和CIDR前缀
func (m *Manager) calculateNetworkCIDR(ip net.IP, mask net.IPMask) string {
	// 计算网络地址
	network := ip.Mask(mask)

	// 计算CIDR前缀长度
	ones, _ := mask.Size()

	// 返回CIDR格式的网络地址
	return fmt.Sprintf("%s/%d", network.String(), ones)
}

// cleanupRoleRules 清除指定接口和角色的相关规则
// 当接口角色发生变更时，清除旧角色的NAT和转发规则
//
// 参数：
//   - interfaceName: 接口名称
//   - oldRole: 旧的端口角色
//
// 返回值：
//   - error: 清除失败时返回错误信息
func (m *Manager) cleanupRoleRules(interfaceName string, oldRole interfaces.PortRole) error {
	switch oldRole {
	case interfaces.PortRoleWAN:
		// 清除WAN接口的规则
		return m.cleanupWANRules(interfaceName)
	case interfaces.PortRoleLAN:
		// 清除LAN接口的规则
		return m.cleanupLANRules(interfaceName)
	case interfaces.PortRoleDMZ:
		// 清除DMZ接口的规则（如果有的话）
		log.Printf("清除DMZ接口 %s 的规则", interfaceName)
		return nil
	case interfaces.PortRoleUnassigned:
		// 未分配角色，无需清除
		return nil
	default:
		return nil
	}
}

// cleanupWANRules 清除WAN接口的相关规则
func (m *Manager) cleanupWANRules(wanInterface string) error {
	// 获取所有LAN接口，清除与它们相关的规则
	lanInterfaces := m.interfaceManager.GetLANInterfaces()

	for _, lanIface := range lanInterfaces {
		if lanIface.IPAddress != nil && lanIface.Netmask != nil {
			// 计算LAN网络地址
			lanNetwork := m.calculateNetworkCIDR(lanIface.IPAddress, lanIface.Netmask)

			// 移除MASQUERADE规则
			if err := m.natManager.RemoveMasqueradeRule(wanInterface, lanNetwork); err != nil {
				log.Printf("移除MASQUERADE规则失败 %s -> %s: %v", lanNetwork, wanInterface, err)
			} else {
				log.Printf("成功移除MASQUERADE规则: %s -> %s", lanNetwork, wanInterface)
			}
		}

		// 移除转发规则
		if err := m.natManager.RemoveForwardRule(lanIface.Name, wanInterface); err != nil {
			log.Printf("移除转发规则失败 %s <-> %s: %v", lanIface.Name, wanInterface, err)
		} else {
			log.Printf("成功移除转发规则: %s <-> %s", lanIface.Name, wanInterface)
		}
	}

	return nil
}

// cleanupLANRules 清除LAN接口的相关规则
func (m *Manager) cleanupLANRules(lanInterface string) error {
	// 获取LAN接口信息
	lanIface, err := m.interfaceManager.GetInterface(lanInterface)
	if err != nil {
		return fmt.Errorf("获取LAN接口信息失败: %v", err)
	}

	// 获取所有WAN接口，清除与它们相关的规则
	wanInterfaces := m.interfaceManager.GetWANInterfaces()

	for _, wanIface := range wanInterfaces {
		if lanIface.IPAddress != nil && lanIface.Netmask != nil {
			// 计算LAN网络地址
			lanNetwork := m.calculateNetworkCIDR(lanIface.IPAddress, lanIface.Netmask)

			// 移除MASQUERADE规则
			if err := m.natManager.RemoveMasqueradeRule(wanIface.Name, lanNetwork); err != nil {
				log.Printf("移除MASQUERADE规则失败 %s -> %s: %v", lanNetwork, wanIface.Name, err)
			} else {
				log.Printf("成功移除MASQUERADE规则: %s -> %s", lanNetwork, wanIface.Name)
			}
		}

		// 移除转发规则
		if err := m.natManager.RemoveForwardRule(lanInterface, wanIface.Name); err != nil {
			log.Printf("移除转发规则失败 %s <-> %s: %v", lanInterface, wanIface.Name, err)
		} else {
			log.Printf("成功移除转发规则: %s <-> %s", lanInterface, wanIface.Name)
		}
	}

	return nil
}
