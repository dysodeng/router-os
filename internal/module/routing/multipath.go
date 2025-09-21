package routing

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// MultipathRoute 多路径路由
type MultipathRoute struct {
	// Destination 目标网络
	Destination *net.IPNet

	// Paths 路径列表
	Paths []*RoutePath

	// Algorithm 路径选择算法
	Algorithm MultipathAlgorithm

	// IsEnabled 是否启用
	IsEnabled bool

	// CreatedAt 创建时间
	CreatedAt time.Time

	// UpdatedAt 更新时间
	UpdatedAt time.Time

	// Stats 统计信息
	Stats MultipathStats

	// mu 读写锁
	mu sync.RWMutex //nolint:unused // 为多路径路由状态同步保留
}

// RoutePath 路由路径
type RoutePath struct {
	// Gateway 网关地址
	Gateway net.IP

	// Interface 出口接口
	Interface string

	// Weight 权重（用于加权负载均衡）
	Weight int

	// Cost 路径成本（用于成本敏感算法）
	Cost int

	// Bandwidth 带宽（Mbps）
	Bandwidth int

	// Latency 延迟（毫秒）
	Latency time.Duration

	// PacketLoss 丢包率（百分比）
	PacketLoss float64

	// IsActive 是否激活
	IsActive bool

	// IsHealthy 是否健康
	IsHealthy bool

	// LastHealthCheck 最后健康检查时间
	LastHealthCheck time.Time

	// Stats 路径统计信息
	Stats PathStats
}

// PathStats 路径统计信息
type PathStats struct {
	// PacketsSent 发送的数据包数
	PacketsSent int64

	// BytesSent 发送的字节数
	BytesSent int64

	// PacketsReceived 接收的数据包数
	PacketsReceived int64

	// BytesReceived 接收的字节数
	BytesReceived int64

	// Errors 错误数
	Errors int64

	// LastUsed 最后使用时间
	LastUsed time.Time

	// AverageLatency 平均延迟
	AverageLatency time.Duration

	// CurrentUtilization 当前利用率（百分比）
	CurrentUtilization float64
}

// MultipathStats 多路径统计信息
type MultipathStats struct {
	// TotalPaths 总路径数
	TotalPaths int

	// ActivePaths 激活路径数
	ActivePaths int

	// HealthyPaths 健康路径数
	HealthyPaths int

	// TotalPackets 总数据包数
	TotalPackets int64

	// TotalBytes 总字节数
	TotalBytes int64

	// LoadDistribution 负载分布（每个路径的使用百分比）
	LoadDistribution map[string]float64

	// LastUpdate 最后更新时间
	LastUpdate time.Time
}

// MultipathAlgorithm 多路径算法
type MultipathAlgorithm int

const (
	// EqualCostMultiPath 等价多路径（ECMP）
	// 特点：在多个等价路径间平均分配流量
	// 优点：简单高效，负载均衡好
	// 缺点：不考虑路径质量差异
	// 适用场景：路径质量相近的情况
	EqualCostMultiPath MultipathAlgorithm = iota

	// WeightedMultiPath 加权多路径
	// 特点：根据权重分配流量
	// 优点：可以根据路径容量分配负载
	// 缺点：需要手动配置权重
	// 适用场景：路径容量差异较大的情况
	WeightedMultiPath

	// AdaptiveMultiPath 自适应多路径
	// 特点：根据路径实时性能动态调整流量分配
	// 优点：自动优化，适应性强
	// 缺点：复杂度高，可能不稳定
	// 适用场景：网络环境变化较大的情况
	AdaptiveMultiPath

	// FlowBasedMultiPath 基于流的多路径
	// 特点：按流（五元组）分配路径，保证同一流的数据包走同一路径
	// 优点：避免乱序，保持连接状态
	// 缺点：可能导致负载不均衡
	// 适用场景：对数据包顺序敏感的应用
	FlowBasedMultiPath

	// LatencyBasedMultiPath 基于延迟的多路径
	// 特点：优先选择延迟最低的路径
	// 优点：优化响应时间
	// 缺点：可能导致某些路径过载
	// 适用场景：对延迟敏感的应用
	LatencyBasedMultiPath

	// BandwidthBasedMultiPath 基于带宽的多路径
	// 特点：根据路径可用带宽分配流量
	// 优点：最大化带宽利用率
	// 缺点：需要实时带宽监控
	// 适用场景：带宽敏感的应用
	BandwidthBasedMultiPath
)

// FlowKey 流标识
type FlowKey struct {
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
}

// String 返回FlowKey的字符串表示
func (fk FlowKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d/%s",
		fk.SourceIP.String(), fk.SourcePort,
		fk.DestinationIP.String(), fk.DestinationPort,
		fk.Protocol)
}

// MultipathManager 多路径管理器
type MultipathManager struct {
	// routes 多路径路由表
	routes map[string]*MultipathRoute

	// flowTable 流表（用于基于流的多路径）
	flowTable map[string]*RoutePath

	// mu 读写锁
	mu sync.RWMutex

	// pathSelector 路径选择器
	pathSelector PathSelector //nolint:unused // 为路径选择算法保留

	// healthChecker 健康检查器
	healthChecker *PathHealthChecker

	// stats 全局统计信息
	stats GlobalMultipathStats
}

// PathSelector 路径选择器接口
type PathSelector interface {
	// SelectPath 选择路径
	SelectPath(route *MultipathRoute, flowKey *FlowKey) (*RoutePath, error)

	// UpdatePathMetrics 更新路径指标
	UpdatePathMetrics(path *RoutePath, latency time.Duration, packetLoss float64, bandwidth int)
}

// PathHealthChecker 路径健康检查器
type PathHealthChecker struct {
	// interval 检查间隔
	interval time.Duration

	// timeout 检查超时
	timeout time.Duration

	// retries 重试次数
	retries int

	// mu 读写锁
	mu sync.RWMutex //nolint:unused // 为健康检查器状态同步保留

	// stopChan 停止通道
	stopChan chan struct{}
}

// GlobalMultipathStats 全局多路径统计信息
type GlobalMultipathStats struct {
	// TotalRoutes 总路由数
	TotalRoutes int

	// TotalPaths 总路径数
	TotalPaths int

	// ActivePaths 激活路径数
	ActivePaths int

	// TotalFlows 总流数
	TotalFlows int

	// TotalPackets 总数据包数
	TotalPackets int64

	// TotalBytes 总字节数
	TotalBytes int64

	// AveragePathUtilization 平均路径利用率
	AveragePathUtilization float64

	// LastUpdate 最后更新时间
	LastUpdate time.Time
}

// NewMultipathManager 创建多路径管理器
func NewMultipathManager() *MultipathManager {
	mm := &MultipathManager{
		routes:    make(map[string]*MultipathRoute),
		flowTable: make(map[string]*RoutePath),
		stats:     GlobalMultipathStats{},
	}

	// 创建健康检查器
	mm.healthChecker = &PathHealthChecker{
		interval: 30 * time.Second,
		timeout:  5 * time.Second,
		retries:  3,
		stopChan: make(chan struct{}),
	}

	return mm
}

// AddMultipathRoute 添加多路径路由
func (mm *MultipathManager) AddMultipathRoute(destination *net.IPNet, algorithm MultipathAlgorithm) (*MultipathRoute, error) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	key := destination.String()
	if _, exists := mm.routes[key]; exists {
		return nil, fmt.Errorf("multipath route for %s already exists", key)
	}

	route := &MultipathRoute{
		Destination: destination,
		Paths:       make([]*RoutePath, 0),
		Algorithm:   algorithm,
		IsEnabled:   true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Stats: MultipathStats{
			LoadDistribution: make(map[string]float64),
		},
	}

	mm.routes[key] = route
	mm.stats.TotalRoutes++

	return route, nil
}

// AddPath 添加路径到多路径路由
func (mm *MultipathManager) AddPath(destination *net.IPNet, gateway net.IP, iface string, weight int, cost int) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	key := destination.String()
	route, exists := mm.routes[key]
	if !exists {
		return fmt.Errorf("multipath route for %s not found", key)
	}

	// 检查路径是否已存在
	for _, path := range route.Paths {
		if path.Gateway.Equal(gateway) && path.Interface == iface {
			return fmt.Errorf("path already exists: gateway=%s, interface=%s", gateway, iface)
		}
	}

	path := &RoutePath{
		Gateway:         gateway,
		Interface:       iface,
		Weight:          weight,
		Cost:            cost,
		Bandwidth:       1000, // 默认1Gbps
		Latency:         0,
		PacketLoss:      0,
		IsActive:        true,
		IsHealthy:       true,
		LastHealthCheck: time.Now(),
		Stats:           PathStats{},
	}

	route.Paths = append(route.Paths, path)
	route.Stats.TotalPaths++
	route.Stats.ActivePaths++
	route.Stats.HealthyPaths++
	route.UpdatedAt = time.Now()

	mm.stats.TotalPaths++
	mm.stats.ActivePaths++

	// 启动健康检查
	go mm.startPathHealthCheck(path)

	return nil
}

// RemovePath 移除路径
func (mm *MultipathManager) RemovePath(destination *net.IPNet, gateway net.IP, iface string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	key := destination.String()
	route, exists := mm.routes[key]
	if !exists {
		return fmt.Errorf("multipath route for %s not found", key)
	}

	for i, path := range route.Paths {
		if path.Gateway.Equal(gateway) && path.Interface == iface {
			// 移除路径
			route.Paths = append(route.Paths[:i], route.Paths[i+1:]...)
			route.Stats.TotalPaths--
			if path.IsActive {
				route.Stats.ActivePaths--
			}
			if path.IsHealthy {
				route.Stats.HealthyPaths--
			}
			route.UpdatedAt = time.Now()

			mm.stats.TotalPaths--
			if path.IsActive {
				mm.stats.ActivePaths--
			}

			// 清理流表中的相关条目
			mm.cleanupFlowTable(path)

			return nil
		}
	}

	return fmt.Errorf("path not found: gateway=%s, interface=%s", gateway, iface)
}

// SelectPath 选择路径
//
//nolint:unused // 此函数为路径选择保留，将在流量分发模块中使用
func (mm *MultipathManager) SelectPath(destination *net.IPNet, flowKey *FlowKey) (*RoutePath, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	key := destination.String()
	route, exists := mm.routes[key]
	if !exists {
		return nil, fmt.Errorf("multipath route for %s not found", key)
	}

	if !route.IsEnabled {
		return nil, fmt.Errorf("multipath route for %s is disabled", key)
	}

	// 获取健康的路径
	healthyPaths := make([]*RoutePath, 0)
	for _, path := range route.Paths {
		if path.IsActive && path.IsHealthy {
			healthyPaths = append(healthyPaths, path)
		}
	}

	if len(healthyPaths) == 0 {
		return nil, fmt.Errorf("no healthy paths available for %s", key)
	}

	// 根据算法选择路径
	var selectedPath *RoutePath
	var err error

	switch route.Algorithm {
	case EqualCostMultiPath:
		selectedPath = mm.selectECMPPath(healthyPaths, flowKey)
	case WeightedMultiPath:
		selectedPath = mm.selectWeightedPath(healthyPaths, flowKey)
	case AdaptiveMultiPath:
		selectedPath = mm.selectAdaptivePath(healthyPaths, flowKey)
	case FlowBasedMultiPath:
		selectedPath = mm.selectFlowBasedPath(healthyPaths, flowKey)
	case LatencyBasedMultiPath:
		selectedPath = mm.selectLatencyBasedPath(healthyPaths, flowKey)
	case BandwidthBasedMultiPath:
		selectedPath = mm.selectBandwidthBasedPath(healthyPaths, flowKey)
	default:
		selectedPath = healthyPaths[0]
	}

	if selectedPath == nil {
		return nil, fmt.Errorf("failed to select path for %s", key)
	}

	// 更新统计信息
	selectedPath.Stats.PacketsSent++
	selectedPath.Stats.LastUsed = time.Now()
	route.Stats.TotalPackets++
	mm.stats.TotalPackets++

	return selectedPath, err
}

// selectECMPPath 等价多路径选择
func (mm *MultipathManager) selectECMPPath(paths []*RoutePath, flowKey *FlowKey) *RoutePath {
	if len(paths) == 0 {
		return nil
	}

	// 使用流的哈希值选择路径，确保同一流的数据包走同一路径
	hash := mm.calculateFlowHash(flowKey)
	index := hash % uint32(len(paths))
	return paths[index]
}

// selectWeightedPath 加权路径选择
func (mm *MultipathManager) selectWeightedPath(paths []*RoutePath, flowKey *FlowKey) *RoutePath {
	if len(paths) == 0 {
		return nil
	}

	// 计算总权重
	totalWeight := 0
	for _, path := range paths {
		totalWeight += path.Weight
	}

	if totalWeight == 0 {
		return paths[0]
	}

	// 使用流哈希选择权重范围
	hash := mm.calculateFlowHash(flowKey)
	target := int(hash) % totalWeight

	currentWeight := 0
	for _, path := range paths {
		currentWeight += path.Weight
		if currentWeight > target {
			return path
		}
	}

	return paths[len(paths)-1]
}

// selectAdaptivePath 自适应路径选择
func (mm *MultipathManager) selectAdaptivePath(paths []*RoutePath, flowKey *FlowKey) *RoutePath {
	if len(paths) == 0 {
		return nil
	}

	// 计算每个路径的得分（综合考虑延迟、丢包率、利用率）
	bestPath := paths[0]
	bestScore := mm.calculatePathScore(bestPath)

	for _, path := range paths[1:] {
		score := mm.calculatePathScore(path)
		if score > bestScore {
			bestScore = score
			bestPath = path
		}
	}

	return bestPath
}

// selectFlowBasedPath 基于流的路径选择
func (mm *MultipathManager) selectFlowBasedPath(paths []*RoutePath, flowKey *FlowKey) *RoutePath {
	if len(paths) == 0 {
		return nil
	}

	flowKeyStr := flowKey.String()

	// 检查流表中是否已有记录
	if path, exists := mm.flowTable[flowKeyStr]; exists && path.IsActive && path.IsHealthy {
		return path
	}

	// 选择负载最轻的路径
	bestPath := paths[0]
	minUtilization := bestPath.Stats.CurrentUtilization

	for _, path := range paths[1:] {
		if path.Stats.CurrentUtilization < minUtilization {
			minUtilization = path.Stats.CurrentUtilization
			bestPath = path
		}
	}

	// 记录到流表
	mm.flowTable[flowKeyStr] = bestPath
	mm.stats.TotalFlows++

	return bestPath
}

// selectLatencyBasedPath 基于延迟的路径选择
func (mm *MultipathManager) selectLatencyBasedPath(paths []*RoutePath, flowKey *FlowKey) *RoutePath {
	if len(paths) == 0 {
		return nil
	}

	bestPath := paths[0]
	minLatency := bestPath.Latency

	for _, path := range paths[1:] {
		if path.Latency < minLatency {
			minLatency = path.Latency
			bestPath = path
		}
	}

	return bestPath
}

// selectBandwidthBasedPath 基于带宽的路径选择
func (mm *MultipathManager) selectBandwidthBasedPath(paths []*RoutePath, flowKey *FlowKey) *RoutePath {
	if len(paths) == 0 {
		return nil
	}

	bestPath := paths[0]
	maxAvailableBandwidth := float64(bestPath.Bandwidth) * (1.0 - bestPath.Stats.CurrentUtilization/100.0)

	for _, path := range paths[1:] {
		availableBandwidth := float64(path.Bandwidth) * (1.0 - path.Stats.CurrentUtilization/100.0)
		if availableBandwidth > maxAvailableBandwidth {
			maxAvailableBandwidth = availableBandwidth
			bestPath = path
		}
	}

	return bestPath
}

// calculateFlowHash 计算流哈希值
func (mm *MultipathManager) calculateFlowHash(flowKey *FlowKey) uint32 {
	hash := uint32(0)

	// 源IP哈希
	for _, b := range flowKey.SourceIP.To4() {
		hash = hash*31 + uint32(b)
	}

	// 目标IP哈希
	for _, b := range flowKey.DestinationIP.To4() {
		hash = hash*31 + uint32(b)
	}

	// 端口哈希
	hash = hash*31 + uint32(flowKey.SourcePort)
	hash = hash*31 + uint32(flowKey.DestinationPort)

	// 协议哈希
	for _, b := range []byte(flowKey.Protocol) {
		hash = hash*31 + uint32(b)
	}

	return hash
}

// calculatePathScore 计算路径得分
func (mm *MultipathManager) calculatePathScore(path *RoutePath) float64 {
	// 综合得分计算：延迟权重40%，丢包率权重30%，利用率权重30%
	latencyScore := 1.0 / (1.0 + float64(path.Latency.Milliseconds())/100.0)
	lossScore := 1.0 - path.PacketLoss/100.0
	utilizationScore := 1.0 - path.Stats.CurrentUtilization/100.0

	return 0.4*latencyScore + 0.3*lossScore + 0.3*utilizationScore
}

// startPathHealthCheck 启动路径健康检查
func (mm *MultipathManager) startPathHealthCheck(path *RoutePath) {
	ticker := time.NewTicker(mm.healthChecker.interval)
	defer ticker.Stop()

	for {
		select {
		case <-mm.healthChecker.stopChan:
			return
		case <-ticker.C:
			mm.performPathHealthCheck(path)
		}
	}
}

// performPathHealthCheck 执行路径健康检查
func (mm *MultipathManager) performPathHealthCheck(path *RoutePath) {
	// 简化的健康检查实现
	// 实际实现中可以使用ping、traceroute等工具
	start := time.Now()

	// 模拟健康检查
	healthy := true
	latency := time.Since(start)

	mm.mu.Lock()
	defer mm.mu.Unlock()

	wasHealthy := path.IsHealthy
	path.IsHealthy = healthy
	path.LastHealthCheck = time.Now()
	path.Latency = latency

	// 更新统计信息
	if wasHealthy != healthy {
		// 健康状态发生变化，更新计数
		for _, route := range mm.routes {
			for _, p := range route.Paths {
				if p == path {
					if healthy {
						route.Stats.HealthyPaths++
					} else {
						route.Stats.HealthyPaths--
					}
					break
				}
			}
		}
	}
}

// cleanupFlowTable 清理流表
func (mm *MultipathManager) cleanupFlowTable(removedPath *RoutePath) {
	for flowKey, path := range mm.flowTable {
		if path == removedPath {
			delete(mm.flowTable, flowKey)
			mm.stats.TotalFlows--
		}
	}
}

// GetMultipathRoute 获取多路径路由
func (mm *MultipathManager) GetMultipathRoute(destination *net.IPNet) (*MultipathRoute, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	key := destination.String()
	route, exists := mm.routes[key]
	if !exists {
		return nil, fmt.Errorf("multipath route for %s not found", key)
	}

	return route, nil
}

// GetAllRoutes 获取所有多路径路由
func (mm *MultipathManager) GetAllRoutes() map[string]*MultipathRoute {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	routes := make(map[string]*MultipathRoute)
	for key, route := range mm.routes {
		routes[key] = route
	}

	return routes
}

// GetStats 获取全局统计信息
func (mm *MultipathManager) GetStats() GlobalMultipathStats {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	mm.stats.LastUpdate = time.Now()
	return mm.stats
}

// UpdatePathMetrics 更新路径指标
func (mm *MultipathManager) UpdatePathMetrics(gateway net.IP, iface string, latency time.Duration, packetLoss float64, bandwidth int) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	for _, route := range mm.routes {
		for _, path := range route.Paths {
			if path.Gateway.Equal(gateway) && path.Interface == iface {
				path.Latency = latency
				path.PacketLoss = packetLoss
				path.Bandwidth = bandwidth
				return
			}
		}
	}
}

// Stop 停止多路径管理器
func (mm *MultipathManager) Stop() {
	close(mm.healthChecker.stopChan)
}

// String 返回多路径算法的字符串表示
func (alg MultipathAlgorithm) String() string {
	switch alg {
	case EqualCostMultiPath:
		return "EqualCostMultiPath"
	case WeightedMultiPath:
		return "WeightedMultiPath"
	case AdaptiveMultiPath:
		return "AdaptiveMultiPath"
	case FlowBasedMultiPath:
		return "FlowBasedMultiPath"
	case LatencyBasedMultiPath:
		return "LatencyBasedMultiPath"
	case BandwidthBasedMultiPath:
		return "BandwidthBasedMultiPath"
	default:
		return "Unknown"
	}
}
