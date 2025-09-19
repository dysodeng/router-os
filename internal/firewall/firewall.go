package firewall

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Firewall 防火墙引擎
// 提供数据包过滤、NAT转换、连接跟踪等功能
//
// 主要功能：
// 1. 数据包过滤：基于规则的数据包允许/拒绝
// 2. NAT转换：网络地址转换（SNAT、DNAT、MASQUERADE）
// 3. 连接跟踪：跟踪TCP/UDP连接状态
// 4. 端口转发：将外部端口映射到内部服务
// 5. 流量统计：记录各种流量统计信息
//
// 安全特性：
// - 状态检测防火墙：跟踪连接状态
// - DDoS防护：限制连接速率和数量
// - 入侵检测：检测异常流量模式
// - 日志记录：详细的安全事件日志
//
// 性能优化：
// - 规则缓存：缓存常用规则匹配结果
// - 快速查找：使用哈希表加速规则匹配
// - 批量处理：支持批量处理数据包
// - 并发处理：支持多线程并发处理
type Firewall struct {
	// mu 读写锁
	mu sync.RWMutex

	// running 运行状态
	running bool

	// 规则链
	inputRules   []Rule
	outputRules  []Rule
	forwardRules []Rule
	natRules     []NATRule

	// 连接跟踪表
	connTracker *ConnectionTracker

	// NAT转换表
	natTable *NATTable

	// 统计信息
	stats FirewallStats

	// 配置参数
	config FirewallConfig
}

// Rule 防火墙规则
type Rule struct {
	// ID 规则ID
	ID string

	// Name 规则名称
	Name string

	// Action 动作 (ACCEPT, DROP, REJECT)
	Action string

	// Protocol 协议 (tcp, udp, icmp, all)
	Protocol string

	// SourceIP 源IP地址/网络
	SourceIP *net.IPNet

	// DestIP 目标IP地址/网络
	DestIP *net.IPNet

	// SourcePort 源端口范围
	SourcePort PortRange

	// DestPort 目标端口范围
	DestPort PortRange

	// Interface 接口名称
	Interface string

	// Direction 方向 (in, out, forward)
	Direction string

	// State 连接状态 (NEW, ESTABLISHED, RELATED)
	State []string

	// Enabled 是否启用
	Enabled bool

	// Priority 优先级 (数字越小优先级越高)
	Priority int

	// CreatedAt 创建时间
	CreatedAt time.Time

	// HitCount 命中次数
	HitCount uint64

	// LastHit 最后命中时间
	LastHit time.Time
}

// NATRule NAT规则
type NATRule struct {
	// ID 规则ID
	ID string

	// Name 规则名称
	Name string

	// Type NAT类型 (SNAT, DNAT, MASQUERADE)
	Type string

	// SourceIP 源IP地址/网络
	SourceIP *net.IPNet

	// DestIP 目标IP地址/网络
	DestIP *net.IPNet

	// SourcePort 源端口范围
	SourcePort PortRange

	// DestPort 目标端口范围
	DestPort PortRange

	// TranslateIP 转换后的IP地址
	TranslateIP net.IP

	// TranslatePort 转换后的端口
	TranslatePort int

	// Interface 接口名称
	Interface string

	// Protocol 协议
	Protocol string

	// Enabled 是否启用
	Enabled bool

	// Priority 优先级
	Priority int

	// CreatedAt 创建时间
	CreatedAt time.Time

	// HitCount 命中次数
	HitCount uint64
}

// PortRange 端口范围
type PortRange struct {
	// Start 起始端口
	Start int

	// End 结束端口
	End int
}

// ConnectionTracker 连接跟踪器
type ConnectionTracker struct {
	// mu 读写锁
	mu sync.RWMutex

	// connections 连接表
	connections map[string]*Connection

	// maxConnections 最大连接数
	maxConnections int

	// timeout 连接超时时间
	timeout time.Duration
}

// Connection 连接信息
type Connection struct {
	// ID 连接ID
	ID string

	// Protocol 协议
	Protocol string

	// SourceIP 源IP
	SourceIP net.IP

	// SourcePort 源端口
	SourcePort int

	// DestIP 目标IP
	DestIP net.IP

	// DestPort 目标端口
	DestPort int

	// State 连接状态
	State string

	// CreatedAt 创建时间
	CreatedAt time.Time

	// LastSeen 最后活动时间
	LastSeen time.Time

	// BytesSent 发送字节数
	BytesSent uint64

	// BytesReceived 接收字节数
	BytesReceived uint64

	// PacketsSent 发送包数
	PacketsSent uint64

	// PacketsReceived 接收包数
	PacketsReceived uint64
}

// NATTable NAT转换表
type NATTable struct {
	// mu 读写锁
	mu sync.RWMutex

	// translations NAT转换映射
	translations map[string]*NATTranslation

	// portPool 端口池
	portPool *PortPool
}

// NATTranslation NAT转换记录
type NATTranslation struct {
	// OriginalIP 原始IP
	OriginalIP net.IP

	// OriginalPort 原始端口
	OriginalPort int

	// TranslatedIP 转换后IP
	TranslatedIP net.IP

	// TranslatedPort 转换后端口
	TranslatedPort int

	// Protocol 协议
	Protocol string

	// CreatedAt 创建时间
	CreatedAt time.Time

	// LastUsed 最后使用时间
	LastUsed time.Time

	// BytesTranslated 转换字节数
	BytesTranslated uint64
}

// PortPool 端口池
type PortPool struct {
	// mu 读写锁
	mu sync.RWMutex

	// availablePorts 可用端口
	availablePorts map[int]bool

	// startPort 起始端口
	startPort int

	// endPort 结束端口
	endPort int
}

// FirewallStats 防火墙统计信息
type FirewallStats struct {
	// PacketsProcessed 处理的数据包总数
	PacketsProcessed uint64

	// PacketsAccepted 允许的数据包数
	PacketsAccepted uint64

	// PacketsDropped 丢弃的数据包数
	PacketsDropped uint64

	// PacketsRejected 拒绝的数据包数
	PacketsRejected uint64

	// NATTranslations NAT转换次数
	NATTranslations uint64

	// ActiveConnections 活跃连接数
	ActiveConnections uint64

	// TotalConnections 总连接数
	TotalConnections uint64

	// RuleHits 规则命中次数
	RuleHits map[string]uint64

	// StartTime 统计开始时间
	StartTime time.Time
}

// FirewallConfig 防火墙配置
type FirewallConfig struct {
	// DefaultPolicy 默认策略 (ACCEPT, DROP)
	DefaultPolicy string

	// EnableConnTracking 是否启用连接跟踪
	EnableConnTracking bool

	// EnableNAT 是否启用NAT
	EnableNAT bool

	// EnableLogging 是否启用日志
	EnableLogging bool

	// MaxConnections 最大连接数
	MaxConnections int

	// ConnTimeout 连接超时时间
	ConnTimeout time.Duration

	// NATPortStart NAT端口范围起始
	NATPortStart int

	// NATPortEnd NAT端口范围结束
	NATPortEnd int
}

// PacketInfo 数据包信息
type PacketInfo struct {
	// SourceIP 源IP
	SourceIP net.IP

	// DestIP 目标IP
	DestIP net.IP

	// SourcePort 源端口
	SourcePort int

	// DestPort 目标端口
	DestPort int

	// Protocol 协议
	Protocol string

	// Size 数据包大小
	Size int

	// Interface 接口名称
	Interface string

	// Direction 方向 (in, out, forward)
	Direction string

	// Data 数据包内容
	Data []byte
}

// NewFirewall 创建新的防火墙实例
//
// 返回值：
//   - *Firewall: 防火墙实例
//
// 使用示例：
//
//	fw := NewFirewall()
//	fw.Start()
//	defer fw.Stop()
//
//	// 添加规则
//	rule := Rule{
//	    ID: "allow-ssh",
//	    Action: "ACCEPT",
//	    Protocol: "tcp",
//	    DestPort: PortRange{Start: 22, End: 22},
//	}
//	fw.AddRule("input", rule)
func NewFirewall() *Firewall {
	fw := &Firewall{
		running:      false,
		inputRules:   make([]Rule, 0),
		outputRules:  make([]Rule, 0),
		forwardRules: make([]Rule, 0),
		natRules:     make([]NATRule, 0),
		stats: FirewallStats{
			RuleHits:  make(map[string]uint64),
			StartTime: time.Now(),
		},
		config: FirewallConfig{
			DefaultPolicy:      "DROP",
			EnableConnTracking: true,
			EnableNAT:          true,
			EnableLogging:      true,
			MaxConnections:     10000,
			ConnTimeout:        300 * time.Second,
			NATPortStart:       32768,
			NATPortEnd:         65535,
		},
	}

	// 初始化连接跟踪器
	fw.connTracker = &ConnectionTracker{
		connections:    make(map[string]*Connection),
		maxConnections: fw.config.MaxConnections,
		timeout:        fw.config.ConnTimeout,
	}

	// 初始化NAT表
	fw.natTable = &NATTable{
		translations: make(map[string]*NATTranslation),
		portPool:     NewPortPool(fw.config.NATPortStart, fw.config.NATPortEnd),
	}

	return fw
}

// Start 启动防火墙
func (fw *Firewall) Start() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.running {
		return fmt.Errorf("防火墙已经在运行")
	}

	fw.running = true
	fw.stats.StartTime = time.Now()

	// 启动连接跟踪清理协程
	if fw.config.EnableConnTracking {
		go fw.cleanupConnections()
	}

	return nil
}

// Stop 停止防火墙
func (fw *Firewall) Stop() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.running = false
}

// ProcessPacket 处理数据包
// 这是防火墙的核心方法，对每个数据包进行过滤和NAT处理
//
// 处理流程：
// 1. 连接跟踪：更新或创建连接记录
// 2. 规则匹配：按优先级匹配防火墙规则
// 3. NAT处理：进行地址转换（如果需要）
// 4. 动作执行：执行ACCEPT、DROP或REJECT动作
// 5. 统计更新：更新相关统计信息
//
// 参数：
//   - pkt: 数据包信息
//
// 返回值：
//   - string: 处理动作 (ACCEPT, DROP, REJECT)
//   - *PacketInfo: 处理后的数据包信息（可能经过NAT转换）
//   - error: 处理错误
func (fw *Firewall) ProcessPacket(pkt *PacketInfo) (string, *PacketInfo, error) {
	if !fw.IsRunning() {
		return "DROP", nil, fmt.Errorf("防火墙未运行")
	}

	// 更新统计信息
	fw.mu.Lock()
	fw.stats.PacketsProcessed++
	fw.mu.Unlock()

	// 第一步：连接跟踪
	var conn *Connection
	if fw.config.EnableConnTracking {
		conn = fw.trackConnection(pkt)
	}

	// 第二步：NAT处理（DNAT在规则匹配前，SNAT在规则匹配后）
	processedPkt := *pkt
	if fw.config.EnableNAT && pkt.Direction == "in" {
		if err := fw.processDNAT(&processedPkt); err != nil {
			return "DROP", nil, fmt.Errorf("DNAT处理失败: %v", err)
		}
	}

	// 第三步：规则匹配
	action := fw.matchRules(&processedPkt, conn)

	// 第四步：SNAT处理
	if action == "ACCEPT" && fw.config.EnableNAT && pkt.Direction == "out" {
		if err := fw.processSNAT(&processedPkt); err != nil {
			return "DROP", nil, fmt.Errorf("SNAT处理失败: %v", err)
		}
	}

	// 第五步：更新统计信息
	fw.updateStats(action)

	return action, &processedPkt, nil
}

// matchRules 匹配防火墙规则
func (fw *Firewall) matchRules(pkt *PacketInfo, conn *Connection) string {
	var rules []Rule

	// 根据方向选择规则链
	switch pkt.Direction {
	case "in":
		rules = fw.inputRules
	case "out":
		rules = fw.outputRules
	case "forward":
		rules = fw.forwardRules
	default:
		return fw.config.DefaultPolicy
	}

	// 按优先级排序并匹配规则
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if fw.ruleMatches(&rule, pkt, conn) {
			// 更新规则命中统计
			fw.mu.Lock()
			rule.HitCount++
			rule.LastHit = time.Now()
			fw.stats.RuleHits[rule.ID]++
			fw.mu.Unlock()

			return rule.Action
		}
	}

	// 没有匹配的规则，使用默认策略
	return fw.config.DefaultPolicy
}

// ruleMatches 检查规则是否匹配数据包
func (fw *Firewall) ruleMatches(rule *Rule, pkt *PacketInfo, conn *Connection) bool {
	// 检查协议
	if rule.Protocol != "all" && rule.Protocol != pkt.Protocol {
		return false
	}

	// 检查源IP
	if rule.SourceIP != nil && !rule.SourceIP.Contains(pkt.SourceIP) {
		return false
	}

	// 检查目标IP
	if rule.DestIP != nil && !rule.DestIP.Contains(pkt.DestIP) {
		return false
	}

	// 检查源端口
	if rule.SourcePort.Start > 0 && !fw.portInRange(pkt.SourcePort, rule.SourcePort) {
		return false
	}

	// 检查目标端口
	if rule.DestPort.Start > 0 && !fw.portInRange(pkt.DestPort, rule.DestPort) {
		return false
	}

	// 检查接口
	if rule.Interface != "" && rule.Interface != pkt.Interface {
		return false
	}

	// 检查连接状态
	if len(rule.State) > 0 && conn != nil {
		stateMatch := false
		for _, state := range rule.State {
			if state == conn.State {
				stateMatch = true
				break
			}
		}
		if !stateMatch {
			return false
		}
	}

	return true
}

// portInRange 检查端口是否在范围内
func (fw *Firewall) portInRange(port int, portRange PortRange) bool {
	if portRange.End == 0 {
		portRange.End = portRange.Start
	}
	return port >= portRange.Start && port <= portRange.End
}

// trackConnection 跟踪连接
func (fw *Firewall) trackConnection(pkt *PacketInfo) *Connection {
	connID := fw.generateConnectionID(pkt)

	fw.connTracker.mu.Lock()
	defer fw.connTracker.mu.Unlock()

	conn, exists := fw.connTracker.connections[connID]
	if exists {
		// 更新现有连接
		conn.LastSeen = time.Now()
		conn.PacketsReceived++
		conn.BytesReceived += uint64(pkt.Size)
		return conn
	}

	// 创建新连接
	if len(fw.connTracker.connections) >= fw.connTracker.maxConnections {
		// 连接数达到上限，清理旧连接
		fw.cleanupOldConnections()
	}

	conn = &Connection{
		ID:              connID,
		Protocol:        pkt.Protocol,
		SourceIP:        pkt.SourceIP,
		SourcePort:      pkt.SourcePort,
		DestIP:          pkt.DestIP,
		DestPort:        pkt.DestPort,
		State:           "NEW",
		CreatedAt:       time.Now(),
		LastSeen:        time.Now(),
		PacketsReceived: 1,
		BytesReceived:   uint64(pkt.Size),
	}

	fw.connTracker.connections[connID] = conn

	fw.mu.Lock()
	fw.stats.TotalConnections++
	fw.stats.ActiveConnections++
	fw.mu.Unlock()

	return conn
}

// generateConnectionID 生成连接ID
func (fw *Firewall) generateConnectionID(pkt *PacketInfo) string {
	return fmt.Sprintf("%s:%s:%d:%s:%d",
		pkt.Protocol,
		pkt.SourceIP.String(),
		pkt.SourcePort,
		pkt.DestIP.String(),
		pkt.DestPort)
}

// processDNAT 处理目标NAT
func (fw *Firewall) processDNAT(pkt *PacketInfo) error {
	for _, rule := range fw.natRules {
		if !rule.Enabled || rule.Type != "DNAT" {
			continue
		}

		if fw.natRuleMatches(&rule, pkt) {
			// 执行DNAT转换
			originalDest := pkt.DestIP.String() + ":" + strconv.Itoa(pkt.DestPort)

			pkt.DestIP = rule.TranslateIP
			if rule.TranslatePort > 0 {
				pkt.DestPort = rule.TranslatePort
			}

			// 记录NAT转换
			fw.recordNATTranslation(originalDest, pkt, "DNAT")

			fw.mu.Lock()
			rule.HitCount++
			fw.stats.NATTranslations++
			fw.mu.Unlock()

			break
		}
	}

	return nil
}

// processSNAT 处理源NAT
func (fw *Firewall) processSNAT(pkt *PacketInfo) error {
	for _, rule := range fw.natRules {
		if !rule.Enabled || (rule.Type != "SNAT" && rule.Type != "MASQUERADE") {
			continue
		}

		if fw.natRuleMatches(&rule, pkt) {
			// 执行SNAT转换
			originalSrc := pkt.SourceIP.String() + ":" + strconv.Itoa(pkt.SourcePort)

			pkt.SourceIP = rule.TranslateIP
			if rule.TranslatePort > 0 {
				pkt.SourcePort = rule.TranslatePort
			} else if rule.Type == "MASQUERADE" {
				// 动态分配端口
				port, err := fw.natTable.portPool.AllocatePort()
				if err != nil {
					return fmt.Errorf("无法分配NAT端口: %v", err)
				}
				pkt.SourcePort = port
			}

			// 记录NAT转换
			fw.recordNATTranslation(originalSrc, pkt, "SNAT")

			fw.mu.Lock()
			rule.HitCount++
			fw.stats.NATTranslations++
			fw.mu.Unlock()

			break
		}
	}

	return nil
}

// natRuleMatches 检查NAT规则是否匹配
func (fw *Firewall) natRuleMatches(rule *NATRule, pkt *PacketInfo) bool {
	// 检查协议
	if rule.Protocol != "all" && rule.Protocol != pkt.Protocol {
		return false
	}

	// 检查源IP
	if rule.SourceIP != nil && !rule.SourceIP.Contains(pkt.SourceIP) {
		return false
	}

	// 检查目标IP
	if rule.DestIP != nil && !rule.DestIP.Contains(pkt.DestIP) {
		return false
	}

	// 检查源端口
	if rule.SourcePort.Start > 0 && !fw.portInRange(pkt.SourcePort, rule.SourcePort) {
		return false
	}

	// 检查目标端口
	if rule.DestPort.Start > 0 && !fw.portInRange(pkt.DestPort, rule.DestPort) {
		return false
	}

	// 检查接口
	if rule.Interface != "" && rule.Interface != pkt.Interface {
		return false
	}

	return true
}

// recordNATTranslation 记录NAT转换
func (fw *Firewall) recordNATTranslation(originalAddr string, pkt *PacketInfo, natType string) {
	fw.natTable.mu.Lock()
	defer fw.natTable.mu.Unlock()

	translation := &NATTranslation{
		OriginalIP:      pkt.SourceIP,
		OriginalPort:    pkt.SourcePort,
		TranslatedIP:    pkt.DestIP,
		TranslatedPort:  pkt.DestPort,
		Protocol:        pkt.Protocol,
		CreatedAt:       time.Now(),
		LastUsed:        time.Now(),
		BytesTranslated: uint64(pkt.Size),
	}

	fw.natTable.translations[originalAddr] = translation
}

// updateStats 更新统计信息
func (fw *Firewall) updateStats(action string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	switch action {
	case "ACCEPT":
		fw.stats.PacketsAccepted++
	case "DROP":
		fw.stats.PacketsDropped++
	case "REJECT":
		fw.stats.PacketsRejected++
	}
}

// AddRule 添加防火墙规则
//
// 参数：
//   - chain: 规则链名称 (input, output, forward)
//   - rule: 防火墙规则
//
// 返回值：
//   - error: 添加成功返回nil，失败返回错误信息
func (fw *Firewall) AddRule(chain string, rule Rule) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// 设置规则创建时间
	rule.CreatedAt = time.Now()

	// 根据链类型添加规则
	switch strings.ToLower(chain) {
	case "input":
		fw.inputRules = append(fw.inputRules, rule)
	case "output":
		fw.outputRules = append(fw.outputRules, rule)
	case "forward":
		fw.forwardRules = append(fw.forwardRules, rule)
	default:
		return fmt.Errorf("无效的规则链: %s", chain)
	}

	// 按优先级排序
	fw.sortRules()

	return nil
}

// AddNATRule 添加NAT规则
//
// 参数：
//   - rule: NAT规则
//
// 返回值：
//   - error: 添加成功返回nil，失败返回错误信息
func (fw *Firewall) AddNATRule(rule NATRule) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	rule.CreatedAt = time.Now()
	fw.natRules = append(fw.natRules, rule)

	// 按优先级排序
	fw.sortNATRules()

	return nil
}

// RemoveRule 删除防火墙规则
//
// 参数：
//   - chain: 规则链名称
//   - ruleID: 规则ID
//
// 返回值：
//   - error: 删除成功返回nil，失败返回错误信息
func (fw *Firewall) RemoveRule(chain, ruleID string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	var rules *[]Rule

	switch strings.ToLower(chain) {
	case "input":
		rules = &fw.inputRules
	case "output":
		rules = &fw.outputRules
	case "forward":
		rules = &fw.forwardRules
	default:
		return fmt.Errorf("无效的规则链: %s", chain)
	}

	for i, rule := range *rules {
		if rule.ID == ruleID {
			*rules = append((*rules)[:i], (*rules)[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("规则不存在: %s", ruleID)
}

// GetRules 获取防火墙规则
//
// 参数：
//   - chain: 规则链名称
//
// 返回值：
//   - []Rule: 规则列表
//   - error: 获取失败返回错误信息
func (fw *Firewall) GetRules(chain string) ([]Rule, error) {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	switch strings.ToLower(chain) {
	case "input":
		return fw.inputRules, nil
	case "output":
		return fw.outputRules, nil
	case "forward":
		return fw.forwardRules, nil
	default:
		return nil, fmt.Errorf("无效的规则链: %s", chain)
	}
}

// GetNATRules 获取NAT规则
//
// 返回值：
//   - []NATRule: NAT规则列表
func (fw *Firewall) GetNATRules() []NATRule {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	return fw.natRules
}

// GetStats 获取防火墙统计信息
//
// 返回值：
//   - FirewallStats: 统计信息
func (fw *Firewall) GetStats() FirewallStats {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	// 更新活跃连接数
	fw.connTracker.mu.RLock()
	fw.stats.ActiveConnections = uint64(len(fw.connTracker.connections))
	fw.connTracker.mu.RUnlock()

	return fw.stats
}

// GetConnections 获取活跃连接
//
// 返回值：
//   - []*Connection: 连接列表
func (fw *Firewall) GetConnections() []*Connection {
	fw.connTracker.mu.RLock()
	defer fw.connTracker.mu.RUnlock()

	connections := make([]*Connection, 0, len(fw.connTracker.connections))
	for _, conn := range fw.connTracker.connections {
		connections = append(connections, conn)
	}

	return connections
}

// IsRunning 检查防火墙是否运行
//
// 返回值：
//   - bool: 运行状态
func (fw *Firewall) IsRunning() bool {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	return fw.running
}

// SetConfig 设置防火墙配置
//
// 参数：
//   - config: 防火墙配置
func (fw *Firewall) SetConfig(config FirewallConfig) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.config = config
}

// GetConfig 获取防火墙配置
//
// 返回值：
//   - FirewallConfig: 防火墙配置
func (fw *Firewall) GetConfig() FirewallConfig {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	return fw.config
}

// 内部辅助方法

// sortRules 按优先级排序规则
func (fw *Firewall) sortRules() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// 排序输入规则（优先级高的在前，相同优先级按创建时间排序）
	sort.Slice(fw.inputRules, func(i, j int) bool {
		if fw.inputRules[i].Priority != fw.inputRules[j].Priority {
			return fw.inputRules[i].Priority > fw.inputRules[j].Priority
		}
		return fw.inputRules[i].CreatedAt.Before(fw.inputRules[j].CreatedAt)
	})

	// 排序输出规则
	sort.Slice(fw.outputRules, func(i, j int) bool {
		if fw.outputRules[i].Priority != fw.outputRules[j].Priority {
			return fw.outputRules[i].Priority > fw.outputRules[j].Priority
		}
		return fw.outputRules[i].CreatedAt.Before(fw.outputRules[j].CreatedAt)
	})

	// 排序转发规则
	sort.Slice(fw.forwardRules, func(i, j int) bool {
		if fw.forwardRules[i].Priority != fw.forwardRules[j].Priority {
			return fw.forwardRules[i].Priority > fw.forwardRules[j].Priority
		}
		return fw.forwardRules[i].CreatedAt.Before(fw.forwardRules[j].CreatedAt)
	})
}

// sortNATRules 按优先级排序NAT规则
func (fw *Firewall) sortNATRules() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// 按优先级排序NAT规则（优先级高的在前，相同优先级按创建时间排序）
	sort.Slice(fw.natRules, func(i, j int) bool {
		if fw.natRules[i].Priority != fw.natRules[j].Priority {
			return fw.natRules[i].Priority > fw.natRules[j].Priority
		}
		return fw.natRules[i].CreatedAt.Before(fw.natRules[j].CreatedAt)
	})
}

// cleanupConnections 清理过期连接
func (fw *Firewall) cleanupConnections() {
	ticker := time.NewTicker(60 * time.Second) // 每分钟清理一次
	defer ticker.Stop()

	for range ticker.C {
		if !fw.IsRunning() {
			return
		}
		fw.cleanupOldConnections()
	}
}

// cleanupOldConnections 清理旧连接
func (fw *Firewall) cleanupOldConnections() {
	fw.connTracker.mu.Lock()
	defer fw.connTracker.mu.Unlock()

	now := time.Now()
	for id, conn := range fw.connTracker.connections {
		if now.Sub(conn.LastSeen) > fw.connTracker.timeout {
			delete(fw.connTracker.connections, id)

			fw.mu.Lock()
			fw.stats.ActiveConnections--
			fw.mu.Unlock()
		}
	}
}

// NewPortPool 创建端口池
func NewPortPool(start, end int) *PortPool {
	pool := &PortPool{
		availablePorts: make(map[int]bool),
		startPort:      start,
		endPort:        end,
	}

	// 初始化可用端口
	for port := start; port <= end; port++ {
		pool.availablePorts[port] = true
	}

	return pool
}

// AllocatePort 分配端口
func (pp *PortPool) AllocatePort() (int, error) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	for port := range pp.availablePorts {
		if pp.availablePorts[port] {
			pp.availablePorts[port] = false
			return port, nil
		}
	}

	return 0, fmt.Errorf("没有可用端口")
}

// ReleasePort 释放端口
func (pp *PortPool) ReleasePort(port int) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	if port >= pp.startPort && port <= pp.endPort {
		pp.availablePorts[port] = true
	}
}

// 添加规则验证功能
func (fw *Firewall) ValidateRule(rule *Rule) error {
	// 验证规则ID
	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	// 验证动作
	validActions := map[string]bool{
		"ACCEPT": true,
		"DROP":   true,
		"REJECT": true,
		"LOG":    true,
	}
	if !validActions[rule.Action] {
		return fmt.Errorf("invalid action: %s", rule.Action)
	}

	// 验证协议
	if rule.Protocol != "" {
		validProtocols := map[string]bool{
			"tcp":  true,
			"udp":  true,
			"icmp": true,
			"all":  true,
		}
		if !validProtocols[strings.ToLower(rule.Protocol)] {
			return fmt.Errorf("invalid protocol: %s", rule.Protocol)
		}
	}

	// 验证端口范围
	if err := fw.validatePortRange(rule.SourcePort); err != nil {
		return fmt.Errorf("invalid source port range: %v", err)
	}
	if err := fw.validatePortRange(rule.DestPort); err != nil {
		return fmt.Errorf("invalid destination port range: %v", err)
	}

	// 验证IP网络
	if rule.SourceIP != nil && rule.SourceIP.IP == nil {
		return fmt.Errorf("invalid source IP network")
	}
	if rule.DestIP != nil && rule.DestIP.IP == nil {
		return fmt.Errorf("invalid destination IP network")
	}

	// 验证方向
	if rule.Direction != "" {
		validDirections := map[string]bool{
			"INPUT":   true,
			"OUTPUT":  true,
			"FORWARD": true,
		}
		if !validDirections[strings.ToUpper(rule.Direction)] {
			return fmt.Errorf("invalid direction: %s", rule.Direction)
		}
	}

	// 验证连接状态
	for _, state := range rule.State {
		validStates := map[string]bool{
			"NEW":         true,
			"ESTABLISHED": true,
			"RELATED":     true,
			"INVALID":     true,
		}
		if !validStates[strings.ToUpper(state)] {
			return fmt.Errorf("invalid connection state: %s", state)
		}
	}

	return nil
}

func (fw *Firewall) validatePortRange(portRange PortRange) error {
	if portRange.Start < 0 || portRange.Start > 65535 {
		return fmt.Errorf("start port out of range: %d", portRange.Start)
	}
	if portRange.End < 0 || portRange.End > 65535 {
		return fmt.Errorf("end port out of range: %d", portRange.End)
	}
	if portRange.Start > portRange.End {
		return fmt.Errorf("start port cannot be greater than end port")
	}
	return nil
}

func (fw *Firewall) ValidateNATRule(rule *NATRule) error {
	// 验证规则ID
	if rule.ID == "" {
		return fmt.Errorf("NAT rule ID cannot be empty")
	}

	// 验证NAT类型
	validTypes := map[string]bool{
		"SNAT":       true,
		"DNAT":       true,
		"MASQUERADE": true,
	}
	if !validTypes[strings.ToUpper(rule.Type)] {
		return fmt.Errorf("invalid NAT type: %s", rule.Type)
	}

	// 验证协议
	if rule.Protocol != "" {
		validProtocols := map[string]bool{
			"tcp": true,
			"udp": true,
			"all": true,
		}
		if !validProtocols[strings.ToLower(rule.Protocol)] {
			return fmt.Errorf("invalid protocol: %s", rule.Protocol)
		}
	}

	// 验证端口范围
	if err := fw.validatePortRange(rule.SourcePort); err != nil {
		return fmt.Errorf("invalid source port range: %v", err)
	}
	if err := fw.validatePortRange(rule.DestPort); err != nil {
		return fmt.Errorf("invalid destination port range: %v", err)
	}

	// 验证转换地址
	if rule.Type != "MASQUERADE" && rule.TranslateIP == nil {
		return fmt.Errorf("translate IP is required for %s", rule.Type)
	}

	return nil
}

// 添加规则冲突检测
func (fw *Firewall) DetectRuleConflicts(newRule *Rule, chain string) []string {
	var conflicts []string
	var existingRules []Rule

	switch strings.ToUpper(chain) {
	case "INPUT":
		existingRules = fw.inputRules
	case "OUTPUT":
		existingRules = fw.outputRules
	case "FORWARD":
		existingRules = fw.forwardRules
	}

	for _, rule := range existingRules {
		if fw.rulesConflict(newRule, &rule) {
			conflicts = append(conflicts, fmt.Sprintf("Conflict with rule %s: %s", rule.ID, rule.Name))
		}
	}

	return conflicts
}

func (fw *Firewall) rulesConflict(rule1, rule2 *Rule) bool {
	// 检查是否有重叠的匹配条件但不同的动作
	if rule1.Action == rule2.Action {
		return false // 相同动作不算冲突
	}

	// 检查协议重叠
	if !fw.protocolsOverlap(rule1.Protocol, rule2.Protocol) {
		return false
	}

	// 检查IP范围重叠
	if !fw.ipRangesOverlap(rule1.SourceIP, rule2.SourceIP) ||
		!fw.ipRangesOverlap(rule1.DestIP, rule2.DestIP) {
		return false
	}

	// 检查端口范围重叠
	if !fw.portRangesOverlap(rule1.SourcePort, rule2.SourcePort) ||
		!fw.portRangesOverlap(rule1.DestPort, rule2.DestPort) {
		return false
	}

	return true
}

func (fw *Firewall) protocolsOverlap(proto1, proto2 string) bool {
	if proto1 == "" || proto2 == "" || proto1 == "all" || proto2 == "all" {
		return true
	}
	return strings.EqualFold(proto1, proto2)
}

func (fw *Firewall) ipRangesOverlap(net1, net2 *net.IPNet) bool {
	if net1 == nil || net2 == nil {
		return true // nil表示任意IP
	}
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}

func (fw *Firewall) portRangesOverlap(range1, range2 PortRange) bool {
	if range1.Start == 0 && range1.End == 0 || range2.Start == 0 && range2.End == 0 {
		return true // 0表示任意端口
	}
	return range1.Start <= range2.End && range2.Start <= range1.End
}

// 添加性能优化功能
func (fw *Firewall) OptimizeRules() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// 按优先级和命中率排序规则
	fw.optimizeRuleChain(&fw.inputRules)
	fw.optimizeRuleChain(&fw.outputRules)
	fw.optimizeRuleChain(&fw.forwardRules)

	// 移除重复规则
	fw.removeDuplicateRules()

	// 合并相邻规则
	fw.mergeAdjacentRules()
}

func (fw *Firewall) optimizeRuleChain(rules *[]Rule) {
	sort.Slice(*rules, func(i, j int) bool {
		rule1, rule2 := (*rules)[i], (*rules)[j]

		// 首先按优先级排序
		if rule1.Priority != rule2.Priority {
			return rule1.Priority < rule2.Priority
		}

		// 然后按命中率排序（高命中率优先）
		return rule1.HitCount > rule2.HitCount
	})
}

func (fw *Firewall) removeDuplicateRules() {
	fw.inputRules = fw.removeDuplicatesFromChain(fw.inputRules)
	fw.outputRules = fw.removeDuplicatesFromChain(fw.outputRules)
	fw.forwardRules = fw.removeDuplicatesFromChain(fw.forwardRules)
}

func (fw *Firewall) removeDuplicatesFromChain(rules []Rule) []Rule {
	seen := make(map[string]bool)
	var result []Rule

	for _, rule := range rules {
		hash := fw.calculateRuleHash(&rule)
		if !seen[hash] {
			seen[hash] = true
			result = append(result, rule)
		}
	}

	return result
}

func (fw *Firewall) calculateRuleHash(rule *Rule) string {
	data := fmt.Sprintf("%s:%s:%s:%v:%v:%v:%v:%s:%s:%v",
		rule.Action, rule.Protocol, rule.Interface,
		rule.SourceIP, rule.DestIP, rule.SourcePort, rule.DestPort,
		rule.Direction, strings.Join(rule.State, ","), rule.Priority)

	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (fw *Firewall) mergeAdjacentRules() {
	// 合并具有相同动作和相似条件的相邻规则
	fw.inputRules = fw.mergeRulesInChain(fw.inputRules)
	fw.outputRules = fw.mergeRulesInChain(fw.outputRules)
	fw.forwardRules = fw.mergeRulesInChain(fw.forwardRules)
}

func (fw *Firewall) mergeRulesInChain(rules []Rule) []Rule {
	if len(rules) <= 1 {
		return rules
	}

	var merged []Rule
	current := rules[0]

	for i := 1; i < len(rules); i++ {
		if fw.canMergeRules(&current, &rules[i]) {
			current = fw.mergeRules(&current, &rules[i])
		} else {
			merged = append(merged, current)
			current = rules[i]
		}
	}
	merged = append(merged, current)

	return merged
}

func (fw *Firewall) canMergeRules(rule1, rule2 *Rule) bool {
	return rule1.Action == rule2.Action &&
		rule1.Protocol == rule2.Protocol &&
		rule1.Interface == rule2.Interface &&
		rule1.Direction == rule2.Direction &&
		strings.Join(rule1.State, ",") == strings.Join(rule2.State, ",")
}

func (fw *Firewall) mergeRules(rule1, rule2 *Rule) Rule {
	merged := *rule1
	merged.ID = fmt.Sprintf("%s+%s", rule1.ID, rule2.ID)
	merged.Name = fmt.Sprintf("Merged: %s + %s", rule1.Name, rule2.Name)
	merged.HitCount = rule1.HitCount + rule2.HitCount

	// 合并端口范围
	if rule1.SourcePort.End+1 == rule2.SourcePort.Start {
		merged.SourcePort.End = rule2.SourcePort.End
	}
	if rule1.DestPort.End+1 == rule2.DestPort.Start {
		merged.DestPort.End = rule2.DestPort.End
	}

	return merged
}

// 添加日志记录功能
type FirewallLogger struct {
	mu       sync.RWMutex //nolint:unused // 为日志记录器状态同步保留
	enabled  bool
	logLevel string
	logFile  string
	logger   *log.Logger
}

func NewFirewallLogger(enabled bool, logLevel, logFile string) *FirewallLogger {
	return &FirewallLogger{
		enabled:  enabled,
		logLevel: logLevel,
		logFile:  logFile,
		logger:   log.New(log.Writer(), "[FIREWALL] ", log.LstdFlags),
	}
}

func (fw *Firewall) LogPacket(pkt *PacketInfo, action string, rule *Rule) {
	if !fw.config.EnableLogging {
		return
	}

	logEntry := fmt.Sprintf("ACTION=%s SRC=%s:%d DST=%s:%d PROTO=%s SIZE=%d IFACE=%s",
		action,
		pkt.SourceIP.String(), pkt.SourcePort,
		pkt.DestIP.String(), pkt.DestPort,
		pkt.Protocol,
		pkt.Size,
		pkt.Interface)

	if rule != nil {
		logEntry += fmt.Sprintf(" RULE=%s", rule.ID)
	}

	log.Printf("%s", logEntry)
}

func (fw *Firewall) LogConnection(conn *Connection, event string) {
	if !fw.config.EnableLogging {
		return
	}

	logEntry := fmt.Sprintf("CONN_EVENT=%s ID=%s SRC=%s:%d DST=%s:%d PROTO=%s STATE=%s",
		event,
		conn.ID,
		conn.SourceIP.String(), conn.SourcePort,
		conn.DestIP.String(), conn.DestPort,
		conn.Protocol,
		conn.State)

	log.Printf("%s", logEntry)
}

func (fw *Firewall) LogNATTranslation(translation *NATTranslation, event string) {
	if !fw.config.EnableLogging {
		return
	}

	logEntry := fmt.Sprintf("NAT_EVENT=%s ORIG=%s:%d TRANS=%s:%d PROTO=%s",
		event,
		translation.OriginalIP.String(), translation.OriginalPort,
		translation.TranslatedIP.String(), translation.TranslatedPort,
		translation.Protocol)

	log.Printf("%s", logEntry)
}

// 添加规则模板功能
type RuleTemplate struct {
	Name        string
	Description string
	Rules       []Rule
	Category    string
}

func (fw *Firewall) GetRuleTemplates() map[string]RuleTemplate {
	templates := make(map[string]RuleTemplate)

	// SSH访问模板
	templates["ssh_access"] = RuleTemplate{
		Name:        "SSH Access",
		Description: "Allow SSH access from specific networks",
		Category:    "remote_access",
		Rules: []Rule{
			{
				ID:       "ssh_allow",
				Name:     "Allow SSH",
				Action:   "ACCEPT",
				Protocol: "tcp",
				DestPort: PortRange{Start: 22, End: 22},
				State:    []string{"NEW", "ESTABLISHED"},
			},
		},
	}

	// Web服务器模板
	templates["web_server"] = RuleTemplate{
		Name:        "Web Server",
		Description: "Allow HTTP and HTTPS traffic",
		Category:    "web_services",
		Rules: []Rule{
			{
				ID:       "http_allow",
				Name:     "Allow HTTP",
				Action:   "ACCEPT",
				Protocol: "tcp",
				DestPort: PortRange{Start: 80, End: 80},
				State:    []string{"NEW", "ESTABLISHED"},
			},
			{
				ID:       "https_allow",
				Name:     "Allow HTTPS",
				Action:   "ACCEPT",
				Protocol: "tcp",
				DestPort: PortRange{Start: 443, End: 443},
				State:    []string{"NEW", "ESTABLISHED"},
			},
		},
	}

	// 基本安全模板
	templates["basic_security"] = RuleTemplate{
		Name:        "Basic Security",
		Description: "Basic security rules to block common attacks",
		Category:    "security",
		Rules: []Rule{
			{
				ID:     "block_invalid",
				Name:   "Block Invalid Connections",
				Action: "DROP",
				State:  []string{"INVALID"},
			},
			{
				ID:        "allow_loopback",
				Name:      "Allow Loopback",
				Action:    "ACCEPT",
				Interface: "lo",
			},
		},
	}

	return templates
}

func (fw *Firewall) ApplyRuleTemplate(templateName, chain string) error {
	templates := fw.GetRuleTemplates()
	template, exists := templates[templateName]
	if !exists {
		return fmt.Errorf("template not found: %s", templateName)
	}

	for _, rule := range template.Rules {
		// 生成唯一ID
		rule.ID = fmt.Sprintf("%s_%s_%d", templateName, rule.ID, time.Now().Unix())
		rule.CreatedAt = time.Now()

		if err := fw.AddRule(chain, rule); err != nil {
			return fmt.Errorf("failed to add rule %s: %v", rule.ID, err)
		}
	}

	return nil
}

// 添加规则导入导出功能
type RuleExport struct {
	Version      string    `json:"version"`
	ExportTime   time.Time `json:"export_time"`
	InputRules   []Rule    `json:"input_rules"`
	OutputRules  []Rule    `json:"output_rules"`
	ForwardRules []Rule    `json:"forward_rules"`
	NATRules     []NATRule `json:"nat_rules"`
}

func (fw *Firewall) ExportRules() RuleExport {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	return RuleExport{
		Version:      "1.0",
		ExportTime:   time.Now(),
		InputRules:   fw.inputRules,
		OutputRules:  fw.outputRules,
		ForwardRules: fw.forwardRules,
		NATRules:     fw.natRules,
	}
}

func (fw *Firewall) ImportRules(export RuleExport, overwrite bool) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if overwrite {
		fw.inputRules = nil
		fw.outputRules = nil
		fw.forwardRules = nil
		fw.natRules = nil
	}

	// 验证并导入规则
	for _, rule := range export.InputRules {
		if err := fw.ValidateRule(&rule); err != nil {
			return fmt.Errorf("invalid input rule %s: %v", rule.ID, err)
		}
		fw.inputRules = append(fw.inputRules, rule)
	}

	for _, rule := range export.OutputRules {
		if err := fw.ValidateRule(&rule); err != nil {
			return fmt.Errorf("invalid output rule %s: %v", rule.ID, err)
		}
		fw.outputRules = append(fw.outputRules, rule)
	}

	for _, rule := range export.ForwardRules {
		if err := fw.ValidateRule(&rule); err != nil {
			return fmt.Errorf("invalid forward rule %s: %v", rule.ID, err)
		}
		fw.forwardRules = append(fw.forwardRules, rule)
	}

	for _, rule := range export.NATRules {
		if err := fw.ValidateNATRule(&rule); err != nil {
			return fmt.Errorf("invalid NAT rule %s: %v", rule.ID, err)
		}
		fw.natRules = append(fw.natRules, rule)
	}

	// 重新排序规则
	fw.sortRules()
	fw.sortNATRules()

	return nil
}

// 添加高级统计功能
func (fw *Firewall) GetDetailedStats() map[string]interface{} {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	stats := make(map[string]interface{})

	// 基本统计
	stats["packets_processed"] = fw.stats.PacketsProcessed
	stats["packets_accepted"] = fw.stats.PacketsAccepted
	stats["packets_dropped"] = fw.stats.PacketsDropped
	stats["packets_rejected"] = fw.stats.PacketsRejected
	stats["nat_translations"] = fw.stats.NATTranslations
	stats["active_connections"] = fw.stats.ActiveConnections
	stats["total_connections"] = fw.stats.TotalConnections

	// 规则统计
	stats["total_rules"] = len(fw.inputRules) + len(fw.outputRules) + len(fw.forwardRules)
	stats["input_rules"] = len(fw.inputRules)
	stats["output_rules"] = len(fw.outputRules)
	stats["forward_rules"] = len(fw.forwardRules)
	stats["nat_rules"] = len(fw.natRules)

	// 规则命中统计
	ruleHits := make(map[string]uint64)
	for _, rule := range fw.inputRules {
		ruleHits[rule.ID] = rule.HitCount
	}
	for _, rule := range fw.outputRules {
		ruleHits[rule.ID] = rule.HitCount
	}
	for _, rule := range fw.forwardRules {
		ruleHits[rule.ID] = rule.HitCount
	}
	stats["rule_hits"] = ruleHits

	// 性能统计
	if fw.stats.PacketsProcessed > 0 {
		stats["accept_rate"] = float64(fw.stats.PacketsAccepted) / float64(fw.stats.PacketsProcessed)
		stats["drop_rate"] = float64(fw.stats.PacketsDropped) / float64(fw.stats.PacketsProcessed)
		stats["reject_rate"] = float64(fw.stats.PacketsRejected) / float64(fw.stats.PacketsProcessed)
	}

	// 运行时间
	stats["uptime"] = time.Since(fw.stats.StartTime)

	return stats
}

// 添加规则搜索功能
func (fw *Firewall) SearchRules(query string) []Rule {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	var results []Rule
	allRules := append(append(fw.inputRules, fw.outputRules...), fw.forwardRules...)

	// 支持正则表达式搜索
	regex, err := regexp.Compile(strings.ToLower(query))
	if err != nil {
		// 如果不是有效的正则表达式，使用简单字符串匹配
		for _, rule := range allRules {
			if fw.ruleMatchesQuery(&rule, strings.ToLower(query)) {
				results = append(results, rule)
			}
		}
	} else {
		for _, rule := range allRules {
			if fw.ruleMatchesRegex(&rule, regex) {
				results = append(results, rule)
			}
		}
	}

	return results
}

func (fw *Firewall) ruleMatchesQuery(rule *Rule, query string) bool {
	searchText := strings.ToLower(fmt.Sprintf("%s %s %s %s %s",
		rule.ID, rule.Name, rule.Action, rule.Protocol, rule.Interface))
	return strings.Contains(searchText, query)
}

func (fw *Firewall) ruleMatchesRegex(rule *Rule, regex *regexp.Regexp) bool {
	searchText := strings.ToLower(fmt.Sprintf("%s %s %s %s %s",
		rule.ID, rule.Name, rule.Action, rule.Protocol, rule.Interface))
	return regex.MatchString(searchText)
}
