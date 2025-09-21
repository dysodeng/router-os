package nat

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"router-os/internal/interfaces"
)

// Manager 高级NAT管理器
// 提供智能化的NAT规则管理、自动配置和性能优化功能
// 这是网络地址转换管理的核心组件
//
// 主要功能：
// 1. 自动检测网络拓扑并配置NAT规则
// 2. 智能优化NAT规则以提高性能
// 3. 监控NAT连接状态和统计信息
// 4. 提供NAT规则的备份和恢复功能
// 5. 支持多种NAT实现（iptables、nftables等）
type Manager struct {
	// backend NAT后端实现
	// 支持不同的NAT实现方式
	backend NATBackend

	// interfaceManager 接口管理器引用
	// 用于获取网络接口信息
	interfaceManager *interfaces.Manager

	// rules 当前活跃的NAT规则
	// 用于跟踪和管理已配置的规则
	rules map[string]*NATRule

	// mu 读写互斥锁
	// 保护NAT规则的并发访问
	mu sync.RWMutex

	// running 管理器运行状态
	running bool

	// autoConfig 自动配置开关
	// 是否启用自动NAT规则配置
	autoConfig bool

	// stats 统计信息
	stats *NATStats
}

// NATBackend NAT后端接口
// 定义不同NAT实现的标准接口
type NATBackend interface {
	// AddMasqueradeRule 添加MASQUERADE规则
	AddMasqueradeRule(wanInterface string, lanNetwork string) error

	// RemoveMasqueradeRule 移除MASQUERADE规则
	RemoveMasqueradeRule(wanInterface string, lanNetwork string) error

	// AddForwardRule 添加转发规则
	AddForwardRule(fromInterface, toInterface string) error

	// RemoveForwardRule 移除转发规则
	RemoveForwardRule(fromInterface, toInterface string) error

	// CheckMasqueradeRuleExists 检查MASQUERADE规则是否存在
	CheckMasqueradeRuleExists(wanInterface string, lanNetwork string) (bool, error)

	// CheckForwardRuleExists 检查转发规则是否存在
	CheckForwardRuleExists(fromInterface, toInterface string) (bool, error)

	// EnableIPForwarding 启用IP转发
	EnableIPForwarding() error

	// DisableIPForwarding 禁用IP转发
	DisableIPForwarding() error

	// ListNATRules 列出NAT规则
	ListNATRules() ([]string, error)

	// FlushNATRules 清空NAT规则
	FlushNATRules() error
}

// NATRule NAT规则结构
// 表示单个NAT转换规则的完整信息
type NATRule struct {
	// ID 规则唯一标识符
	ID string `json:"id"`

	// Type 规则类型（MASQUERADE、DNAT、SNAT等）
	Type string `json:"type"`

	// WanInterface WAN接口名称
	WanInterface string `json:"wan_interface"`

	// LanNetwork LAN网络地址
	LanNetwork string `json:"lan_network"`

	// FromInterface 源接口
	FromInterface string `json:"from_interface,omitempty"`

	// ToInterface 目标接口
	ToInterface string `json:"to_interface,omitempty"`

	// CreatedAt 创建时间
	CreatedAt time.Time `json:"created_at"`

	// LastUsed 最后使用时间
	LastUsed time.Time `json:"last_used"`

	// PacketCount 数据包计数
	PacketCount uint64 `json:"packet_count"`

	// ByteCount 字节计数
	ByteCount uint64 `json:"byte_count"`

	// Active 规则是否活跃
	Active bool `json:"active"`
}

// NATStats NAT统计信息
// 记录NAT管理器的运行统计数据
type NATStats struct {
	// TotalRules 总规则数
	TotalRules int `json:"total_rules"`

	// ActiveRules 活跃规则数
	ActiveRules int `json:"active_rules"`

	// TotalConnections 总连接数
	TotalConnections uint64 `json:"total_connections"`

	// ActiveConnections 活跃连接数
	ActiveConnections uint64 `json:"active_connections"`

	// TotalPackets 总数据包数
	TotalPackets uint64 `json:"total_packets"`

	// TotalBytes 总字节数
	TotalBytes uint64 `json:"total_bytes"`

	// LastUpdate 最后更新时间
	LastUpdate time.Time `json:"last_update"`
}

// NewManager 创建新的NAT管理器
// 初始化NAT管理器，配置后端实现和接口管理器
//
// 参数：
//   - backend: NAT后端实现
//   - interfaceManager: 接口管理器实例
//
// 返回值：
//   - *Manager: 初始化完成的NAT管理器
//
// 使用示例：
//
//	backend := NewIptablesManager()
//	ifaceManager := interfaces.NewManager()
//	natManager := NewManager(backend, ifaceManager)
func NewManager(backend NATBackend, interfaceManager *interfaces.Manager) *Manager {
	return &Manager{
		backend:          backend,
		interfaceManager: interfaceManager,
		rules:            make(map[string]*NATRule),
		autoConfig:       true,
		stats:            &NATStats{},
	}
}

// syncExistingRules 同步现有的iptables规则到内存状态
// 在系统重启后，iptables规则可能已经存在，但内存状态为空
// 此方法扫描现有的WAN/LAN接口组合，检查对应的规则是否存在，并同步到内存
func (m *Manager) syncExistingRules() error {
	log.Println("开始同步现有的NAT规则到内存状态...")

	// 获取WAN和LAN接口
	wanInterfaces := m.interfaceManager.GetWANInterfaces()
	lanInterfaces := m.interfaceManager.GetLANInterfaces()

	syncedCount := 0

	// 检查并同步MASQUERADE规则
	for _, wanIface := range wanInterfaces {
		for _, lanIface := range lanInterfaces {
			if lanIface.IPAddress != nil && lanIface.Netmask != nil {
				// 计算LAN网络地址
				lanNetwork := m.calculateNetworkAddress(lanIface.IPAddress, lanIface.Netmask)

				// 检查MASQUERADE规则是否存在
				exists, err := m.backend.CheckMasqueradeRuleExists(wanIface.Name, lanNetwork)
				if err != nil {
					log.Printf("检查MASQUERADE规则失败: %v", err)
					continue
				}

				if exists {
					// 规则存在，添加到内存状态
					ruleID := fmt.Sprintf("masq_%s_%s", wanIface.Name, strings.ReplaceAll(lanNetwork, "/", "_"))
					if _, exists := m.rules[ruleID]; !exists {
						rule := &NATRule{
							ID:           ruleID,
							Type:         "MASQUERADE",
							WanInterface: wanIface.Name,
							LanNetwork:   lanNetwork,
							CreatedAt:    time.Now(),
							Active:       true,
						}
						m.rules[ruleID] = rule
						syncedCount++
						log.Printf("同步MASQUERADE规则到内存: %s -> %s", lanNetwork, wanIface.Name)
					}
				}
			}
		}
	}

	// 检查并同步转发规则
	for _, lanIface := range lanInterfaces {
		for _, wanIface := range wanInterfaces {
			// 检查转发规则是否存在
			exists, err := m.backend.CheckForwardRuleExists(lanIface.Name, wanIface.Name)
			if err != nil {
				log.Printf("检查转发规则失败: %v", err)
				continue
			}

			if exists {
				// 规则存在，添加到内存状态
				ruleID := fmt.Sprintf("forward_%s_%s", lanIface.Name, wanIface.Name)
				if _, exists := m.rules[ruleID]; !exists {
					rule := &NATRule{
						ID:            ruleID,
						Type:          "FORWARD",
						FromInterface: lanIface.Name,
						ToInterface:   wanIface.Name,
						CreatedAt:     time.Now(),
						Active:        true,
					}
					m.rules[ruleID] = rule
					syncedCount++
					log.Printf("同步转发规则到内存: %s -> %s", lanIface.Name, wanIface.Name)
				}
			}
		}
	}

	log.Printf("NAT规则同步完成，共同步 %d 条规则", syncedCount)
	return nil
}

// Start 启动NAT管理器
// 初始化NAT管理器并开始自动配置
//
// 返回值：
//   - error: 启动失败时返回错误信息
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("NAT管理器已经在运行")
	}

	// 启用IP转发
	if err := m.backend.EnableIPForwarding(); err != nil {
		return fmt.Errorf("启用IP转发失败: %v", err)
	}

	// 同步现有的iptables规则到内存状态
	// 这样可以避免重复添加已存在的规则
	if err := m.syncExistingRules(); err != nil {
		log.Printf("同步现有规则失败: %v", err)
	}

	// 如果启用自动配置，则自动配置NAT规则
	if m.autoConfig {
		if err := m.autoConfigureNAT(); err != nil {
			log.Printf("自动配置NAT规则失败: %v", err)
		}
	}

	m.running = true
	log.Println("NAT管理器启动成功")
	return nil
}

// Stop 停止NAT管理器
// 停止NAT管理器并可选择性清理规则
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	m.running = false
	log.Println("NAT管理器已停止")
}

// autoConfigureNAT 自动配置NAT规则
// 根据当前网络拓扑自动配置合适的NAT规则
func (m *Manager) autoConfigureNAT() error {
	// 获取WAN和LAN接口
	wanInterfaces := m.interfaceManager.GetWANInterfaces()
	lanInterfaces := m.interfaceManager.GetLANInterfaces()

	if len(wanInterfaces) == 0 {
		return fmt.Errorf("没有找到WAN接口")
	}

	if len(lanInterfaces) == 0 {
		return fmt.Errorf("没有找到LAN接口")
	}

	// 为每个WAN接口配置NAT规则
	for _, wanIface := range wanInterfaces {
		for _, lanIface := range lanInterfaces {
			if lanIface.IPAddress != nil && lanIface.Netmask != nil {
				// 计算LAN网络地址
				lanNetwork := m.calculateNetworkAddress(lanIface.IPAddress, lanIface.Netmask)

				// 添加MASQUERADE规则
				if err := m.AddMasqueradeRule(wanIface.Name, lanNetwork); err != nil {
					log.Printf("自动添加MASQUERADE规则失败: %v", err)
				}

				// 添加转发规则
				if err := m.AddForwardRule(lanIface.Name, wanIface.Name); err != nil {
					log.Printf("自动添加转发规则失败: %v", err)
				}
			}
		}
	}

	return nil
}

// calculateNetworkAddress 计算网络地址
// 根据IP地址和子网掩码计算网络地址
func (m *Manager) calculateNetworkAddress(ip net.IP, mask net.IPMask) string {
	network := ip.Mask(mask)
	ones, _ := mask.Size()
	return fmt.Sprintf("%s/%d", network.String(), ones)
}

// AddMasqueradeRule 添加MASQUERADE规则
// 为指定的WAN接口和LAN网络添加源地址转换规则
//
// 参数：
//   - wanInterface: WAN接口名称
//   - lanNetwork: LAN网络地址
//
// 返回值：
//   - error: 添加失败时返回错误信息
func (m *Manager) AddMasqueradeRule(wanInterface string, lanNetwork string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 生成规则ID
	ruleID := fmt.Sprintf("masq_%s_%s", wanInterface, strings.ReplaceAll(lanNetwork, "/", "_"))

	// 检查规则是否已存在
	if _, exists := m.rules[ruleID]; exists {
		return fmt.Errorf("MASQUERADE规则已存在: %s", ruleID)
	}

	// 添加后端规则
	if err := m.backend.AddMasqueradeRule(wanInterface, lanNetwork); err != nil {
		return err
	}

	// 记录规则
	rule := &NATRule{
		ID:           ruleID,
		Type:         "MASQUERADE",
		WanInterface: wanInterface,
		LanNetwork:   lanNetwork,
		CreatedAt:    time.Now(),
		Active:       true,
	}
	m.rules[ruleID] = rule

	// 更新统计信息
	m.updateStats()

	log.Printf("成功添加MASQUERADE规则: %s -> %s", lanNetwork, wanInterface)
	return nil
}

// RemoveMasqueradeRule 移除MASQUERADE规则
// 删除指定的源地址转换规则
//
// 参数：
//   - wanInterface: WAN接口名称
//   - lanNetwork: LAN网络地址
//
// 返回值：
//   - error: 删除失败时返回错误信息
func (m *Manager) RemoveMasqueradeRule(wanInterface string, lanNetwork string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ruleID := fmt.Sprintf("masq_%s_%s", wanInterface, strings.ReplaceAll(lanNetwork, "/", "_"))

	// 检查规则是否存在
	if _, exists := m.rules[ruleID]; !exists {
		return fmt.Errorf("MASQUERADE规则不存在: %s", ruleID)
	}

	// 移除后端规则
	if err := m.backend.RemoveMasqueradeRule(wanInterface, lanNetwork); err != nil {
		return err
	}

	// 删除规则记录
	delete(m.rules, ruleID)

	// 更新统计信息
	m.updateStats()

	log.Printf("成功移除MASQUERADE规则: %s -> %s", lanNetwork, wanInterface)
	return nil
}

// AddForwardRule 添加转发规则
// 配置接口间的数据包转发规则
//
// 参数：
//   - fromInterface: 源接口名称
//   - toInterface: 目标接口名称
//
// 返回值：
//   - error: 添加失败时返回错误信息
func (m *Manager) AddForwardRule(fromInterface, toInterface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ruleID := fmt.Sprintf("forward_%s_%s", fromInterface, toInterface)

	// 检查规则是否已存在
	if _, exists := m.rules[ruleID]; exists {
		return fmt.Errorf("转发规则已存在: %s", ruleID)
	}

	// 添加后端规则
	if err := m.backend.AddForwardRule(fromInterface, toInterface); err != nil {
		return err
	}

	// 记录规则
	rule := &NATRule{
		ID:            ruleID,
		Type:          "FORWARD",
		FromInterface: fromInterface,
		ToInterface:   toInterface,
		CreatedAt:     time.Now(),
		Active:        true,
	}
	m.rules[ruleID] = rule

	// 更新统计信息
	m.updateStats()

	log.Printf("成功添加转发规则: %s -> %s", fromInterface, toInterface)
	return nil
}

// RemoveForwardRule 移除转发规则
// 删除接口间的数据包转发规则
//
// 参数：
//   - fromInterface: 源接口名称
//   - toInterface: 目标接口名称
//
// 返回值：
//   - error: 删除失败时返回错误信息
func (m *Manager) RemoveForwardRule(fromInterface, toInterface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ruleID := fmt.Sprintf("forward_%s_%s", fromInterface, toInterface)

	// 检查规则是否存在
	if _, exists := m.rules[ruleID]; !exists {
		return fmt.Errorf("转发规则不存在: %s", ruleID)
	}

	// 移除后端规则
	if err := m.backend.RemoveForwardRule(fromInterface, toInterface); err != nil {
		return err
	}

	// 删除规则记录
	delete(m.rules, ruleID)

	// 更新统计信息
	m.updateStats()

	log.Printf("成功移除转发规则: %s -> %s", fromInterface, toInterface)
	return nil
}

// GetNATRules 获取所有NAT规则
// 返回当前管理器中的所有NAT规则
//
// 返回值：
//   - map[string]*NATRule: 规则映射表
func (m *Manager) GetNATRules() map[string]*NATRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 创建规则副本
	rules := make(map[string]*NATRule)
	for id, rule := range m.rules {
		ruleCopy := *rule
		rules[id] = &ruleCopy
	}

	return rules
}

// GetNATStats 获取NAT统计信息
// 返回当前NAT管理器的统计数据
//
// 返回值：
//   - *NATStats: 统计信息
func (m *Manager) GetNATStats() *NATStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 创建统计信息副本
	statsCopy := *m.stats
	return &statsCopy
}

// updateStats 更新统计信息
// 重新计算和更新NAT管理器的统计数据
func (m *Manager) updateStats() {
	m.stats.TotalRules = len(m.rules)
	m.stats.ActiveRules = 0

	for _, rule := range m.rules {
		if rule.Active {
			m.stats.ActiveRules++
		}
	}

	m.stats.LastUpdate = time.Now()
}

// OptimizeRules 优化NAT规则
// 分析和优化当前的NAT规则以提高性能
//
// 返回值：
//   - error: 优化失败时返回错误信息
func (m *Manager) OptimizeRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Println("开始优化NAT规则...")

	// 移除重复规则
	duplicates := m.findDuplicateRules()
	for _, ruleID := range duplicates {
		delete(m.rules, ruleID)
		log.Printf("移除重复规则: %s", ruleID)
	}

	// 移除长时间未使用的规则
	inactive := m.findInactiveRules(24 * time.Hour) // 24小时未使用
	for _, ruleID := range inactive {
		if rule, exists := m.rules[ruleID]; exists {
			rule.Active = false
			log.Printf("标记非活跃规则: %s", ruleID)
		}
	}

	// 更新统计信息
	m.updateStats()

	log.Printf("NAT规则优化完成，当前活跃规则数: %d", m.stats.ActiveRules)
	return nil
}

// findDuplicateRules 查找重复规则
// 识别功能相同的重复NAT规则
func (m *Manager) findDuplicateRules() []string {
	var duplicates []string
	seen := make(map[string]string)

	for id, rule := range m.rules {
		key := fmt.Sprintf("%s_%s_%s_%s", rule.Type, rule.WanInterface,
			rule.LanNetwork, rule.FromInterface)

		if existingID, exists := seen[key]; exists {
			// 保留较新的规则，删除较旧的
			if rule.CreatedAt.After(m.rules[existingID].CreatedAt) {
				duplicates = append(duplicates, existingID)
				seen[key] = id
			} else {
				duplicates = append(duplicates, id)
			}
		} else {
			seen[key] = id
		}
	}

	return duplicates
}

// findInactiveRules 查找非活跃规则
// 识别长时间未使用的NAT规则
func (m *Manager) findInactiveRules(threshold time.Duration) []string {
	var inactive []string
	cutoff := time.Now().Add(-threshold)

	for id, rule := range m.rules {
		if rule.LastUsed.Before(cutoff) && rule.PacketCount == 0 {
			inactive = append(inactive, id)
		}
	}

	return inactive
}

// IsRunning 检查NAT管理器是否正在运行
// 返回管理器的当前运行状态
//
// 返回值：
//   - bool: true表示正在运行，false表示已停止
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// SetAutoConfig 设置自动配置
// 启用或禁用NAT规则的自动配置功能
//
// 参数：
//   - enabled: 是否启用自动配置
func (m *Manager) SetAutoConfig(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.autoConfig = enabled
	log.Printf("自动配置已%s", map[bool]string{true: "启用", false: "禁用"}[enabled])
}

// EnableIPForwarding 启用IP转发
// 在系统级别启用IP数据包转发功能
//
// 返回值：
//   - error: 启用失败时返回错误信息
func (m *Manager) EnableIPForwarding() error {
	return m.backend.EnableIPForwarding()
}

// DisableIPForwarding 禁用IP转发
// 在系统级别禁用IP数据包转发功能
//
// 返回值：
//   - error: 禁用失败时返回错误信息
func (m *Manager) DisableIPForwarding() error {
	return m.backend.DisableIPForwarding()
}
