package routing

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// RoutePolicy 路由策略
type RoutePolicy struct {
	// ID 策略唯一标识
	ID string

	// Name 策略名称
	Name string

	// Description 策略描述
	Description string

	// Priority 策略优先级（数字越小优先级越高）
	Priority int

	// Conditions 匹配条件
	Conditions []PolicyCondition

	// Actions 执行动作
	Actions []PolicyAction

	// IsEnabled 是否启用
	IsEnabled bool

	// CreatedAt 创建时间
	CreatedAt time.Time

	// UpdatedAt 更新时间
	UpdatedAt time.Time

	// MatchCount 匹配次数
	MatchCount int64

	// LastMatchTime 最后匹配时间
	LastMatchTime time.Time
}

// PolicyCondition 策略条件
type PolicyCondition struct {
	// Type 条件类型
	Type ConditionType

	// Field 匹配字段
	Field string

	// Operator 操作符
	Operator ConditionOperator

	// Value 匹配值
	Value interface{}

	// Negate 是否取反
	Negate bool
}

// ConditionType 条件类型
type ConditionType int

const (
	// SourceIP 源IP地址条件
	// 用于匹配数据包的源IP地址
	// 支持单个IP、IP范围、CIDR网段
	SourceIP ConditionType = iota

	// DestinationIP 目标IP地址条件
	// 用于匹配数据包的目标IP地址
	// 支持单个IP、IP范围、CIDR网段
	DestinationIP

	// SourcePort 源端口条件
	// 用于匹配数据包的源端口
	// 支持单个端口、端口范围
	SourcePort

	// DestinationPort 目标端口条件
	// 用于匹配数据包的目标端口
	// 支持单个端口、端口范围
	DestinationPort

	// Protocol 协议条件
	// 用于匹配数据包的协议类型
	// 支持TCP、UDP、ICMP等
	Protocol

	// Interface 接口条件
	// 用于匹配数据包的入口或出口接口
	Interface

	// TimeRange 时间范围条件
	// 用于匹配特定时间段
	// 支持每日时间段、星期、日期范围
	TimeRange

	// PacketSize 数据包大小条件
	// 用于匹配数据包大小
	// 支持大小范围匹配
	PacketSize

	// DSCP DSCP标记条件
	// 用于匹配QoS标记
	DSCP

	// CustomCondition 自定义条件
	// 用户自定义匹配逻辑
	CustomCondition
)

// ConditionOperator 条件操作符
type ConditionOperator int

const (
	// Equal 等于
	Equal ConditionOperator = iota

	// NotEqual 不等于
	NotEqual

	// GreaterThan 大于
	GreaterThan

	// LessThan 小于
	LessThan

	// GreaterEqual 大于等于
	GreaterEqual

	// LessEqual 小于等于
	LessEqual

	// Contains 包含
	Contains

	// NotContains 不包含
	NotContains

	// In 在列表中
	In

	// NotIn 不在列表中
	NotIn

	// Matches 正则匹配
	Matches

	// NotMatches 正则不匹配
	NotMatches
)

// PolicyAction 策略动作
type PolicyAction struct {
	// Type 动作类型
	Type ActionType

	// Parameters 动作参数
	Parameters map[string]interface{}
}

// ActionType 动作类型
type ActionType int

const (
	// Allow 允许通过
	// 允许数据包通过，继续路由处理
	Allow ActionType = iota

	// Deny 拒绝通过
	// 拒绝数据包，丢弃处理
	Deny

	// Redirect 重定向
	// 将数据包重定向到指定网关或接口
	Redirect

	// SetGateway 设置网关
	// 为匹配的数据包设置特定网关
	SetGateway

	// SetInterface 设置接口
	// 为匹配的数据包设置特定出口接口
	SetInterface

	// SetPriority 设置优先级
	// 为匹配的数据包设置QoS优先级
	SetPriority

	// SetDSCP 设置DSCP标记
	// 为匹配的数据包设置DSCP标记
	SetDSCP

	// LoadBalance 负载均衡
	// 对匹配的数据包进行负载均衡处理
	LoadBalance

	// RateLimit 速率限制
	// 对匹配的数据包进行速率限制
	RateLimit

	// Log 记录日志
	// 记录匹配的数据包信息
	Log

	// Mirror 镜像
	// 将数据包镜像到指定目标
	Mirror

	// Custom 自定义动作
	// 用户自定义处理逻辑
	Custom
)

// PacketInfo 数据包信息
type PacketInfo struct {
	// SourceIP 源IP地址
	SourceIP net.IP

	// DestinationIP 目标IP地址
	DestinationIP net.IP

	// SourcePort 源端口
	SourcePort int

	// DestinationPort 目标端口
	DestinationPort int

	// Protocol 协议
	Protocol string

	// Interface 接口
	Interface string

	// PacketSize 数据包大小
	PacketSize int

	// DSCP DSCP标记
	DSCP int

	// Timestamp 时间戳
	Timestamp time.Time

	// Custom 自定义字段
	Custom map[string]interface{}
}

// PolicyResult 策略执行结果
type PolicyResult struct {
	// Matched 是否匹配
	Matched bool

	// Policy 匹配的策略
	Policy *RoutePolicy

	// Actions 要执行的动作
	Actions []PolicyAction

	// Gateway 指定的网关（如果有）
	Gateway net.IP

	// Interface 指定的接口（如果有）
	Interface string

	// Priority 指定的优先级（如果有）
	Priority int

	// Allow 是否允许通过
	Allow bool

	// Message 处理消息
	Message string
}

// PolicyManager 路由策略管理器
type PolicyManager struct {
	// policies 策略列表
	policies []*RoutePolicy

	// mu 读写锁
	mu sync.RWMutex

	// stats 统计信息
	stats PolicyStats

	// customConditionCheckers 自定义条件检查器
	customConditionCheckers map[string]func(packet *PacketInfo, condition *PolicyCondition) bool

	// customActionHandlers 自定义动作处理器
	customActionHandlers map[string]func(packet *PacketInfo, action *PolicyAction) error
}

// PolicyStats 策略统计信息
type PolicyStats struct {
	// TotalPolicies 总策略数
	TotalPolicies int

	// EnabledPolicies 启用策略数
	EnabledPolicies int

	// TotalMatches 总匹配次数
	TotalMatches int64

	// TotalPackets 总处理数据包数
	TotalPackets int64

	// AllowedPackets 允许通过的数据包数
	AllowedPackets int64

	// DeniedPackets 拒绝的数据包数
	DeniedPackets int64

	// RedirectedPackets 重定向的数据包数
	RedirectedPackets int64

	// LastProcessTime 最后处理时间
	LastProcessTime time.Time
}

// NewPolicyManager 创建策略管理器
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies:                make([]*RoutePolicy, 0),
		stats:                   PolicyStats{},
		customConditionCheckers: make(map[string]func(packet *PacketInfo, condition *PolicyCondition) bool),
		customActionHandlers:    make(map[string]func(packet *PacketInfo, action *PolicyAction) error),
	}
}

// AddPolicy 添加策略
func (pm *PolicyManager) AddPolicy(policy *RoutePolicy) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 检查策略ID是否已存在
	for _, p := range pm.policies {
		if p.ID == policy.ID {
			return fmt.Errorf("policy with ID %s already exists", policy.ID)
		}
	}

	// 设置创建时间
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	pm.policies = append(pm.policies, policy)
	pm.stats.TotalPolicies++

	if policy.IsEnabled {
		pm.stats.EnabledPolicies++
	}

	// 按优先级排序
	pm.sortPoliciesByPriority()

	return nil
}

// RemovePolicy 移除策略
func (pm *PolicyManager) RemovePolicy(policyID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i, policy := range pm.policies {
		if policy.ID == policyID {
			if policy.IsEnabled {
				pm.stats.EnabledPolicies--
			}

			pm.policies = append(pm.policies[:i], pm.policies[i+1:]...)
			pm.stats.TotalPolicies--
			return nil
		}
	}

	return fmt.Errorf("policy with ID %s not found", policyID)
}

// UpdatePolicy 更新策略
func (pm *PolicyManager) UpdatePolicy(policy *RoutePolicy) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i, p := range pm.policies {
		if p.ID == policy.ID {
			wasEnabled := p.IsEnabled

			// 保留统计信息
			policy.MatchCount = p.MatchCount
			policy.LastMatchTime = p.LastMatchTime
			policy.CreatedAt = p.CreatedAt
			policy.UpdatedAt = time.Now()

			pm.policies[i] = policy

			// 更新启用策略计数
			if wasEnabled && !policy.IsEnabled {
				pm.stats.EnabledPolicies--
			} else if !wasEnabled && policy.IsEnabled {
				pm.stats.EnabledPolicies++
			}

			// 重新排序
			pm.sortPoliciesByPriority()

			return nil
		}
	}

	return fmt.Errorf("policy with ID %s not found", policy.ID)
}

// EnablePolicy 启用策略
func (pm *PolicyManager) EnablePolicy(policyID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, policy := range pm.policies {
		if policy.ID == policyID {
			if !policy.IsEnabled {
				policy.IsEnabled = true
				policy.UpdatedAt = time.Now()
				pm.stats.EnabledPolicies++
			}
			return nil
		}
	}

	return fmt.Errorf("policy with ID %s not found", policyID)
}

// DisablePolicy 禁用策略
func (pm *PolicyManager) DisablePolicy(policyID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, policy := range pm.policies {
		if policy.ID == policyID {
			if policy.IsEnabled {
				policy.IsEnabled = false
				policy.UpdatedAt = time.Now()
				pm.stats.EnabledPolicies--
			}
			return nil
		}
	}

	return fmt.Errorf("policy with ID %s not found", policyID)
}

// ProcessPacket 处理数据包
func (pm *PolicyManager) ProcessPacket(packet *PacketInfo) *PolicyResult {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pm.stats.TotalPackets++
	pm.stats.LastProcessTime = time.Now()

	result := &PolicyResult{
		Matched: false,
		Allow:   true, // 默认允许
		Actions: make([]PolicyAction, 0),
	}

	// 按优先级顺序检查策略
	for _, policy := range pm.policies {
		if !policy.IsEnabled {
			continue
		}

		if pm.matchPolicy(packet, policy) {
			result.Matched = true
			result.Policy = policy
			result.Actions = append(result.Actions, policy.Actions...)

			// 更新策略统计
			policy.MatchCount++
			policy.LastMatchTime = time.Now()
			pm.stats.TotalMatches++

			// 执行动作
			pm.executeActions(packet, policy.Actions, result)

			// 如果是拒绝动作，立即返回
			for _, action := range policy.Actions {
				if action.Type == Deny {
					result.Allow = false
					pm.stats.DeniedPackets++
					return result
				}
			}

			// 如果策略匹配且不是继续处理类型，停止处理
			break
		}
	}

	if result.Allow {
		pm.stats.AllowedPackets++
	}

	return result
}

// matchPolicy 检查数据包是否匹配策略
func (pm *PolicyManager) matchPolicy(packet *PacketInfo, policy *RoutePolicy) bool {
	// 所有条件都必须匹配
	for _, condition := range policy.Conditions {
		if !pm.matchCondition(packet, &condition) {
			return false
		}
	}
	return true
}

// matchCondition 检查单个条件
func (pm *PolicyManager) matchCondition(packet *PacketInfo, condition *PolicyCondition) bool {
	var matched bool

	switch condition.Type {
	case SourceIP:
		matched = pm.matchIPCondition(packet.SourceIP, condition)
	case DestinationIP:
		matched = pm.matchIPCondition(packet.DestinationIP, condition)
	case SourcePort:
		matched = pm.matchPortCondition(packet.SourcePort, condition)
	case DestinationPort:
		matched = pm.matchPortCondition(packet.DestinationPort, condition)
	case Protocol:
		matched = pm.matchStringCondition(packet.Protocol, condition)
	case Interface:
		matched = pm.matchStringCondition(packet.Interface, condition)
	case TimeRange:
		matched = pm.matchTimeCondition(packet.Timestamp, condition)
	case PacketSize:
		matched = pm.matchIntCondition(packet.PacketSize, condition)
	case DSCP:
		matched = pm.matchIntCondition(packet.DSCP, condition)
	case CustomCondition:
		if checker, exists := pm.customConditionCheckers[condition.Field]; exists {
			matched = checker(packet, condition)
		}
	default:
		matched = false
	}

	// 应用取反逻辑
	if condition.Negate {
		matched = !matched
	}

	return matched
}

// matchIPCondition 匹配IP条件
func (pm *PolicyManager) matchIPCondition(ip net.IP, condition *PolicyCondition) bool {
	switch condition.Operator {
	case Equal:
		if targetIP, ok := condition.Value.(net.IP); ok {
			return ip.Equal(targetIP)
		}
		if cidr, ok := condition.Value.(*net.IPNet); ok {
			return cidr.Contains(ip)
		}
	case In:
		if ipList, ok := condition.Value.([]net.IP); ok {
			for _, targetIP := range ipList {
				if ip.Equal(targetIP) {
					return true
				}
			}
		}
		if cidrList, ok := condition.Value.([]*net.IPNet); ok {
			for _, cidr := range cidrList {
				if cidr.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// matchPortCondition 匹配端口条件
func (pm *PolicyManager) matchPortCondition(port int, condition *PolicyCondition) bool {
	switch condition.Operator {
	case Equal:
		if targetPort, ok := condition.Value.(int); ok {
			return port == targetPort
		}
	case GreaterThan:
		if targetPort, ok := condition.Value.(int); ok {
			return port > targetPort
		}
	case LessThan:
		if targetPort, ok := condition.Value.(int); ok {
			return port < targetPort
		}
	case GreaterEqual:
		if targetPort, ok := condition.Value.(int); ok {
			return port >= targetPort
		}
	case LessEqual:
		if targetPort, ok := condition.Value.(int); ok {
			return port <= targetPort
		}
	case In:
		if portList, ok := condition.Value.([]int); ok {
			for _, targetPort := range portList {
				if port == targetPort {
					return true
				}
			}
		}
	}
	return false
}

// matchStringCondition 匹配字符串条件
func (pm *PolicyManager) matchStringCondition(value string, condition *PolicyCondition) bool {
	switch condition.Operator {
	case Equal:
		if target, ok := condition.Value.(string); ok {
			return value == target
		}
	case Contains:
		if target, ok := condition.Value.(string); ok {
			return len(value) > 0 && len(target) > 0 &&
				value[0:min(len(value), len(target))] == target[0:min(len(value), len(target))]
		}
	case In:
		if targetList, ok := condition.Value.([]string); ok {
			for _, target := range targetList {
				if value == target {
					return true
				}
			}
		}
	}
	return false
}

// matchIntCondition 匹配整数条件
func (pm *PolicyManager) matchIntCondition(value int, condition *PolicyCondition) bool {
	switch condition.Operator {
	case Equal:
		if target, ok := condition.Value.(int); ok {
			return value == target
		}
	case GreaterThan:
		if target, ok := condition.Value.(int); ok {
			return value > target
		}
	case LessThan:
		if target, ok := condition.Value.(int); ok {
			return value < target
		}
	case GreaterEqual:
		if target, ok := condition.Value.(int); ok {
			return value >= target
		}
	case LessEqual:
		if target, ok := condition.Value.(int); ok {
			return value <= target
		}
	}
	return false
}

// matchTimeCondition 匹配时间条件
func (pm *PolicyManager) matchTimeCondition(timestamp time.Time, condition *PolicyCondition) bool {
	// 简化的时间匹配实现
	// 实际实现中可以支持更复杂的时间范围匹配
	switch condition.Operator {
	case Equal:
		if target, ok := condition.Value.(time.Time); ok {
			return timestamp.Equal(target)
		}
	case GreaterThan:
		if target, ok := condition.Value.(time.Time); ok {
			return timestamp.After(target)
		}
	case LessThan:
		if target, ok := condition.Value.(time.Time); ok {
			return timestamp.Before(target)
		}
	}
	return false
}

// executeActions 执行策略动作
func (pm *PolicyManager) executeActions(packet *PacketInfo, actions []PolicyAction, result *PolicyResult) {
	for _, action := range actions {
		switch action.Type {
		case Allow:
			result.Allow = true
		case Deny:
			result.Allow = false
		case SetGateway:
			if gateway, ok := action.Parameters["gateway"].(net.IP); ok {
				result.Gateway = gateway
			}
		case SetInterface:
			if iface, ok := action.Parameters["interface"].(string); ok {
				result.Interface = iface
			}
		case SetPriority:
			if priority, ok := action.Parameters["priority"].(int); ok {
				result.Priority = priority
			}
		case Redirect:
			pm.stats.RedirectedPackets++
		case Custom:
			if handler, exists := pm.customActionHandlers[action.Parameters["handler"].(string)]; exists {
				_ = handler(packet, &action)
			}
		}
	}
}

// sortPoliciesByPriority 按优先级排序策略
func (pm *PolicyManager) sortPoliciesByPriority() {
	for i := 0; i < len(pm.policies); i++ {
		for j := i + 1; j < len(pm.policies); j++ {
			if pm.policies[i].Priority > pm.policies[j].Priority {
				pm.policies[i], pm.policies[j] = pm.policies[j], pm.policies[i]
			}
		}
	}
}

// GetPolicies 获取所有策略
func (pm *PolicyManager) GetPolicies() []*RoutePolicy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	policies := make([]*RoutePolicy, len(pm.policies))
	copy(policies, pm.policies)
	return policies
}

// GetPolicy 获取指定策略
func (pm *PolicyManager) GetPolicy(policyID string) (*RoutePolicy, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, policy := range pm.policies {
		if policy.ID == policyID {
			return policy, nil
		}
	}

	return nil, fmt.Errorf("policy with ID %s not found", policyID)
}

// GetStats 获取统计信息
func (pm *PolicyManager) GetStats() PolicyStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.stats
}

// RegisterCustomConditionChecker 注册自定义条件检查器
func (pm *PolicyManager) RegisterCustomConditionChecker(name string, checker func(packet *PacketInfo, condition *PolicyCondition) bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.customConditionCheckers[name] = checker
}

// RegisterCustomActionHandler 注册自定义动作处理器
func (pm *PolicyManager) RegisterCustomActionHandler(name string, handler func(packet *PacketInfo, action *PolicyAction) error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.customActionHandlers[name] = handler
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// String 返回条件类型的字符串表示
func (ct ConditionType) String() string {
	switch ct {
	case SourceIP:
		return "SourceIP"
	case DestinationIP:
		return "DestinationIP"
	case SourcePort:
		return "SourcePort"
	case DestinationPort:
		return "DestinationPort"
	case Protocol:
		return "Protocol"
	case Interface:
		return "Interface"
	case TimeRange:
		return "TimeRange"
	case PacketSize:
		return "PacketSize"
	case DSCP:
		return "DSCP"
	case CustomCondition:
		return "CustomCondition"
	default:
		return "Unknown"
	}
}

// String 返回动作类型的字符串表示
func (at ActionType) String() string {
	switch at {
	case Allow:
		return "Allow"
	case Deny:
		return "Deny"
	case Redirect:
		return "Redirect"
	case SetGateway:
		return "SetGateway"
	case SetInterface:
		return "SetInterface"
	case SetPriority:
		return "SetPriority"
	case SetDSCP:
		return "SetDSCP"
	case LoadBalance:
		return "LoadBalance"
	case RateLimit:
		return "RateLimit"
	case Log:
		return "Log"
	case Mirror:
		return "Mirror"
	case Custom:
		return "Custom"
	default:
		return "Unknown"
	}
}
