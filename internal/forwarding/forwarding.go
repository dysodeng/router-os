package forwarding

import (
	"crypto/rand"
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"router-os/internal/arp"
	"router-os/internal/interfaces"
	"router-os/internal/routing"
)

// IPPacket IP数据包结构
// 定义在转发引擎中以避免循环依赖
type IPPacket struct {
	// Source 源IP地址
	Source net.IP

	// Destination 目标IP地址
	Destination net.IP

	// TTL 生存时间
	TTL int

	// Protocol 协议类型 (TCP=6, UDP=17, ICMP=1等)
	Protocol int

	// Size 数据包大小（字节）
	Size int

	// Data 数据包内容
	Data []byte

	// InInterface 入接口名称
	InInterface string

	// Timestamp 接收时间戳
	Timestamp time.Time
}

// NewIPPacket 创建新的IP数据包
func NewIPPacket(src, dst net.IP, ttl, protocol int, data []byte) *IPPacket {
	return &IPPacket{
		Source:      src,
		Destination: dst,
		TTL:         ttl,
		Protocol:    protocol,
		Size:        len(data) + 20, // IP头部20字节 + 数据
		Data:        data,
		Timestamp:   time.Now(),
	}
}

// ForwardingStats 转发统计信息
type ForwardingStats struct {
	// PacketsReceived 接收的数据包总数
	PacketsReceived uint64

	// PacketsForwarded 成功转发的数据包数
	PacketsForwarded uint64

	// PacketsDropped 丢弃的数据包数
	PacketsDropped uint64

	// PacketsToLocal 本地交付的数据包数
	PacketsToLocal uint64

	// ICMPGenerated 生成的ICMP消息数
	ICMPGenerated uint64

	// ARPRequests 发送的ARP请求数
	ARPRequests uint64

	// RouteFailures 路由查找失败次数
	RouteFailures uint64

	// TTLExpired TTL过期的数据包数
	TTLExpired uint64

	// FragmentationNeeded 需要分片的数据包数
	FragmentationNeeded uint64

	// StartTime 统计开始时间
	StartTime time.Time
}

// ForwardingConfig 转发配置
type ForwardingConfig struct {
	// EnableIPForwarding 是否启用IP转发
	EnableIPForwarding bool

	// EnableICMPRedirect 是否启用ICMP重定向
	EnableICMPRedirect bool

	// EnableFragmentation 是否启用IP分片
	EnableFragmentation bool

	// MaxTTL 最大TTL值
	MaxTTL int

	// ARPTimeout ARP解析超时时间
	ARPTimeout time.Duration

	// RouteTimeout 路由缓存超时时间
	RouteTimeout time.Duration
}

// NewForwardingEngine 创建新的转发引擎
//
// 参数：
//   - routingTable: 路由表接口
//   - interfaceManager: 接口管理器
//   - arpTable: ARP表
//
// 返回值：
//   - *ForwardingEngine: 转发引擎实例
//
// 使用示例：
//
//	engine := NewForwardingEngine(routingTable, interfaceManager, arpTable)
//	engine.Start()
//	defer engine.Stop()
func NewForwardingEngine(
	routingTable routing.RoutingTableInterface,
	interfaceManager *interfaces.Manager,
	arpTable *arp.ARPTable,
) *ForwardingEngine {
	return &ForwardingEngine{
		routingTable:     routingTable,
		interfaceManager: interfaceManager,
		arpTable:         arpTable,
		running:          false,
		stats: ForwardingStats{
			StartTime: time.Now(),
		},
		config: ForwardingConfig{
			EnableIPForwarding:  true,
			EnableICMPRedirect:  true,
			EnableFragmentation: true,
			MaxTTL:              255,
			ARPTimeout:          5 * time.Second,
			RouteTimeout:        300 * time.Second,
		},
	}
}

// Start 启动转发引擎
func (fe *ForwardingEngine) Start() error {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	if fe.running {
		return fmt.Errorf("转发引擎已经在运行")
	}

	if !fe.config.EnableIPForwarding {
		return fmt.Errorf("IP转发功能未启用")
	}

	// 启动工作线程池
	for _, worker := range fe.workerPool {
		go worker.Start()
	}

	// 启动数据包分发器
	go fe.packetDispatcher()

	// 启动监控组件
	go fe.metricsCollector.Start()
	go fe.alertManager.Start()

	fe.running = true
	fe.stats.StartTime = time.Now()

	return nil
}

// Stop 停止转发引擎
func (fe *ForwardingEngine) Stop() {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	if !fe.running {
		return
	}

	fe.running = false

	// 停止工作线程池
	for _, worker := range fe.workerPool {
		worker.Stop()
	}

	// 停止监控组件
	fe.metricsCollector.Stop()
	fe.alertManager.Stop()

	// 停止故障切换管理器中的健康检查
	for _, checker := range fe.failoverManager.healthCheckers {
		checker.Stop()
	}
}

// ForwardPacket 转发数据包
// 这是转发引擎的核心方法，处理单个数据包的转发
//
// 转发流程：
// 1. 数据包验证：检查IP头部格式和校验和
// 2. TTL处理：递减TTL并检查是否过期
// 3. 目标检查：判断是否为本地目标
// 4. 路由查找：在路由表中查找最佳路由
// 5. ARP解析：解析下一跳的MAC地址
// 6. 数据发送：构造以太网帧并发送
// 7. 统计更新：更新相关统计信息
//
// 参数：
//   - pkt: 要转发的数据包
//
// 返回值：
//   - error: 转发成功返回nil，失败返回错误信息
//
// 可能的错误：
//   - TTL过期：数据包生存时间耗尽
//   - 无路由：路由表中没有到目标的路径
//   - ARP失败：无法解析下一跳MAC地址
//   - 接口故障：出接口不可用
//   - MTU超限：数据包大小超过接口MTU
func (fe *ForwardingEngine) ForwardPacket(pkt *IPPacket) error {
	if !fe.IsRunning() {
		return fmt.Errorf("转发引擎未运行")
	}

	// 更新接收统计
	fe.mu.Lock()
	fe.stats.PacketsReceived++
	fe.mu.Unlock()

	// 第一步：数据包验证
	if err := fe.validatePacket(pkt); err != nil {
		fe.incrementDropped()
		return fmt.Errorf("数据包验证失败: %v", err)
	}

	// 第二步：TTL处理
	if err := fe.handleTTL(pkt); err != nil {
		fe.incrementDropped()
		fe.mu.Lock()
		fe.stats.TTLExpired++
		fe.mu.Unlock()

		// 发送ICMP Time Exceeded消息
		fe.sendICMPTimeExceeded(pkt)
		return err
	}

	// 第三步：检查是否为本地目标
	if fe.isLocalDestination(pkt.Destination) {
		return fe.deliverLocally(pkt)
	}

	// 第四步：路由查找
	route, err := fe.routingTable.LookupRoute(pkt.Destination)
	if err != nil {
		fe.incrementDropped()
		fe.mu.Lock()
		fe.stats.RouteFailures++
		fe.mu.Unlock()

		// 发送ICMP Destination Unreachable消息
		fe.sendICMPDestUnreachable(pkt)
		return fmt.Errorf("路由查找失败: %v", err)
	}

	// 第五步：获取出接口
	outInterface, err := fe.interfaceManager.GetInterface(route.Interface)
	if err != nil {
		fe.incrementDropped()
		return fmt.Errorf("获取出接口失败: %v", err)
	}

	// 第六步：检查接口状态
	if outInterface.Status != interfaces.InterfaceStatusUp {
		fe.incrementDropped()
		return fmt.Errorf("出接口 %s 未启用", route.Interface)
	}

	// 第七步：MTU检查
	if pkt.Size > outInterface.MTU {
		if fe.config.EnableFragmentation {
			return fe.fragmentAndForward(pkt, outInterface, route.Gateway)
		} else {
			fe.incrementDropped()
			fe.mu.Lock()
			fe.stats.FragmentationNeeded++
			fe.mu.Unlock()

			// 发送ICMP Fragmentation Needed消息
			fe.sendICMPFragNeeded(pkt, outInterface.MTU)
			return fmt.Errorf("数据包大小 %d 超过MTU %d", pkt.Size, outInterface.MTU)
		}
	}

	// 第八步：ARP解析
	nextHop := route.Gateway
	if nextHop == nil {
		// 直连网络，下一跳就是目标地址
		nextHop = pkt.Destination
	}

	mac, err := fe.arpTable.Resolve(nextHop, outInterface.Name, fe.config.ARPTimeout)
	if err != nil {
		fe.incrementDropped()
		fe.mu.Lock()
		fe.stats.ARPRequests++
		fe.mu.Unlock()
		return fmt.Errorf("ARP解析失败: %v", err)
	}

	// 第九步：发送数据包
	if err := fe.sendPacket(pkt, outInterface, mac); err != nil {
		fe.incrementDropped()
		return fmt.Errorf("发送数据包失败: %v", err)
	}

	// 第十步：更新统计信息
	fe.mu.Lock()
	fe.stats.PacketsForwarded++
	fe.mu.Unlock()

	return nil
}

// validatePacket 验证数据包
func (fe *ForwardingEngine) validatePacket(pkt *IPPacket) error {
	if pkt == nil {
		return fmt.Errorf("数据包为空")
	}

	if pkt.Source == nil || pkt.Destination == nil {
		return fmt.Errorf("源地址或目标地址为空")
	}

	if pkt.Size <= 0 {
		return fmt.Errorf("数据包大小无效: %d", pkt.Size)
	}

	if pkt.TTL <= 0 || pkt.TTL > 255 {
		return fmt.Errorf("TTL值无效: %d", pkt.TTL)
	}

	return nil
}

// handleTTL 处理TTL
func (fe *ForwardingEngine) handleTTL(pkt *IPPacket) error {
	if pkt.TTL <= 1 {
		return fmt.Errorf("TTL过期")
	}

	// 递减TTL
	pkt.TTL--

	return nil
}

// isLocalDestination 检查是否为本地目标
func (fe *ForwardingEngine) isLocalDestination(destination net.IP) bool {
	interfaces := fe.interfaceManager.GetAllInterfaces()

	for _, iface := range interfaces {
		if iface.IPAddress != nil && iface.IPAddress.Equal(destination) {
			return true
		}
	}

	return false
}

// deliverLocally 本地交付
func (fe *ForwardingEngine) deliverLocally(pkt *IPPacket) error {
	fe.mu.Lock()
	fe.stats.PacketsToLocal++
	fe.mu.Unlock()

	// 在真实实现中，这里会将数据包交付给本地协议栈
	// 例如：TCP、UDP、ICMP等协议处理模块

	return nil
}

// sendPacket 发送数据包
func (fe *ForwardingEngine) sendPacket(pkt *IPPacket, outInterface *interfaces.Interface, dstMAC net.HardwareAddr) error {
	// 在真实实现中，这里会：
	// 1. 构造以太网帧头
	// 2. 设置源MAC为出接口MAC
	// 3. 设置目标MAC为解析到的MAC
	// 4. 调用网络驱动发送数据

	// 更新接口统计信息
	fe.interfaceManager.UpdateInterfaceStats(
		outInterface.Name,
		outInterface.TxPackets+1,
		outInterface.RxPackets,
		outInterface.TxBytes+uint64(pkt.Size),
		outInterface.RxBytes,
		outInterface.Errors,
	)

	return nil
}

// fragmentAndForward 分片并转发
func (fe *ForwardingEngine) fragmentAndForward(pkt *IPPacket, outInterface *interfaces.Interface, gateway net.IP) error {
	// IP分片实现
	// 这是一个复杂的过程，需要：
	// 1. 计算分片大小
	// 2. 设置分片标志和偏移
	// 3. 为每个分片分配新的ID
	// 4. 分别转发每个分片

	fe.mu.Lock()
	fe.stats.FragmentationNeeded++
	fe.mu.Unlock()

	// 当前为简化实现，直接丢弃需要分片的数据包
	return fmt.Errorf("数据包需要分片，但分片功能未完全实现")
}

// sendICMPTimeExceeded 发送ICMP Time Exceeded消息
func (fe *ForwardingEngine) sendICMPTimeExceeded(pkt *IPPacket) {
	fe.mu.Lock()
	fe.stats.ICMPGenerated++
	fe.mu.Unlock()

	// 在真实实现中，这里会构造并发送ICMP Type 11消息
	// 包含原始数据包的IP头和前8字节数据
}

// sendICMPDestUnreachable 发送ICMP Destination Unreachable消息
func (fe *ForwardingEngine) sendICMPDestUnreachable(pkt *IPPacket) {
	fe.mu.Lock()
	fe.stats.ICMPGenerated++
	fe.mu.Unlock()

	// 在真实实现中，这里会构造并发送ICMP Type 3消息
}

// sendICMPFragNeeded 发送ICMP Fragmentation Needed消息
func (fe *ForwardingEngine) sendICMPFragNeeded(pkt *IPPacket, mtu int) {
	fe.mu.Lock()
	fe.stats.ICMPGenerated++
	fe.mu.Unlock()

	// 在真实实现中，这里会构造并发送ICMP Type 3 Code 4消息
	// 包含MTU信息用于路径MTU发现
}

// incrementDropped 增加丢弃计数
func (fe *ForwardingEngine) incrementDropped() {
	fe.mu.Lock()
	fe.stats.PacketsDropped++
	fe.mu.Unlock()
}

// GetStats 获取统计信息
func (fe *ForwardingEngine) GetStats() ForwardingStats {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	return fe.stats
}

// ResetStats 重置统计信息
func (fe *ForwardingEngine) ResetStats() {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	fe.stats = ForwardingStats{
		StartTime: time.Now(),
	}
}

// IsRunning 检查是否运行
func (fe *ForwardingEngine) IsRunning() bool {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	return fe.running
}

// SetConfig 设置配置
func (fe *ForwardingEngine) SetConfig(config ForwardingConfig) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	fe.config = config
}

// GetConfig 获取配置
func (fe *ForwardingEngine) GetConfig() ForwardingConfig {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	return fe.config
}

// ProcessPacketBatch 批量处理数据包
// 提供批量处理接口以提高性能
//
// 参数：
//   - packets: 要处理的数据包列表
//
// 返回值：
//   - []error: 每个数据包的处理结果，nil表示成功
func (fe *ForwardingEngine) ProcessPacketBatch(packets []*IPPacket) []error {
	results := make([]error, len(packets))

	for i, pkt := range packets {
		results[i] = fe.ForwardPacket(pkt)
	}

	return results
}

// GetForwardingTable 获取转发表信息
// 返回当前的路由和ARP信息，用于调试和监控
func (fe *ForwardingEngine) GetForwardingTable() ([]routing.Route, []*arp.ARPEntry) {
	routes := fe.routingTable.GetAllRoutes()
	arpEntries := fe.arpTable.GetAllEntries()

	return routes, arpEntries
}

// 添加负载均衡相关结构
type LoadBalancer struct {
	mu        sync.RWMutex
	algorithm LoadBalanceAlgorithm
	routes    []RouteEntry
	weights   map[string]int
	counters  map[string]uint64
	health    map[string]bool
}

type LoadBalanceAlgorithm int

const (
	RoundRobin LoadBalanceAlgorithm = iota
	WeightedRoundRobin
	LeastConnections
	IPHash
	Random
)

type RouteEntry struct {
	Route      routing.Route
	Weight     int
	Health     bool
	LastCheck  time.Time
	Latency    time.Duration
	PacketLoss float64
}

// 添加故障切换相关结构
type FailoverManager struct {
	mu              sync.RWMutex
	primaryRoutes   map[string]RouteEntry
	backupRoutes    map[string][]RouteEntry
	healthCheckers  map[string]*HealthChecker
	failoverHistory map[string][]FailoverEvent
}

type FailoverEvent struct {
	Timestamp time.Time
	Route     string
	Event     string
	Reason    string
	Duration  time.Duration
}

type HealthChecker struct {
	mu        sync.RWMutex
	target    net.IP
	interval  time.Duration
	timeout   time.Duration
	threshold int
	failures  int
	lastCheck time.Time
	isHealthy bool
	stopChan  chan struct{}
	running   bool
}

// 添加性能监控相关结构
type PerformanceMonitor struct {
	mu              sync.RWMutex
	metrics         map[string]*RouteMetrics
	alertThresholds AlertThresholds
	alerts          []Alert
	collectors      []MetricCollector
}

type RouteMetrics struct {
	PacketsForwarded uint64
	BytesForwarded   uint64
	Latency          time.Duration
	PacketLoss       float64
	Bandwidth        uint64
	Utilization      float64
	ErrorRate        float64
	LastUpdate       time.Time
}

type AlertThresholds struct {
	MaxLatency     time.Duration
	MaxPacketLoss  float64
	MaxUtilization float64
	MaxErrorRate   float64
}

type Alert struct {
	ID        string
	Timestamp time.Time
	Level     AlertLevel
	Route     string
	Metric    string
	Value     interface{}
	Threshold interface{}
	Message   string
	Resolved  bool
}

type AlertLevel int

const (
	AlertInfo AlertLevel = iota
	AlertWarning
	AlertCritical
)

type MetricCollector interface {
	CollectMetrics(route string) (*RouteMetrics, error)
	GetName() string
}

// 添加流量整形相关结构
type TrafficShaper struct {
	mu       sync.RWMutex
	policies map[string]*ShapingPolicy
	buckets  map[string]*TokenBucket
	queues   map[string]*PriorityQueue
}

type ShapingPolicy struct {
	Rate       uint64 // bits per second
	BurstSize  uint64 // bytes
	Priority   int    // 0-7, 0 is highest
	MaxDelay   time.Duration
	DropPolicy DropPolicy
}

type DropPolicy int

const (
	DropTail DropPolicy = iota
	DropRandom
	DropRED
)

type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	rate       float64
	lastUpdate time.Time
}

type PriorityQueue struct {
	mu      sync.Mutex
	queues  [8][]*QueuedPacket
	weights [8]int
	sizes   [8]int
	maxSize int
}

type QueuedPacket struct {
	Packet    *IPPacket
	Priority  int
	Timestamp time.Time
	Size      int
}

// 添加缓存管理
type ForwardingCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int
	ttl     time.Duration
	lru     *LRUCache
}

type CacheEntry struct {
	Route     routing.Route
	NextHop   net.IP
	Interface string
	MAC       net.HardwareAddr
	Timestamp time.Time
	HitCount  uint64
}

type LRUCache struct {
	capacity int
	items    map[string]*LRUNode
	head     *LRUNode
	tail     *LRUNode
}

type LRUNode struct {
	key   string
	value *CacheEntry
	prev  *LRUNode
	next  *LRUNode
}

// ForwardingEngine IP转发引擎
// 这是路由器的核心组件，负责处理所有的IP数据包转发
//
// 主要功能：
// 1. 路由查找：根据目标IP查找最佳路由
// 2. ARP解析：将下一跳IP解析为MAC地址
// 3. 数据包转发：将数据包发送到正确的出接口
// 4. TTL处理：递减TTL并检查是否过期
// 5. 分片处理：处理超过MTU的大数据包
// 6. ICMP生成：生成各种ICMP错误消息
//
// 转发决策过程：
// 1. 接收数据包并验证IP头部
// 2. 检查目标地址是否为本地地址
// 3. 查找路由表确定下一跳
// 4. 进行ARP解析获取MAC地址
// 5. 构造以太网帧并发送
// 6. 更新统计信息
//
// 性能优化：
// - 路由缓存：缓存常用路由减少查找时间
// - ARP缓存：缓存MAC地址映射
// - 批量处理：支持批量处理多个数据包
// - 并发处理：支持多线程并发转发
type ForwardingEngine struct {
	// routingTable 路由表接口
	routingTable routing.RoutingTableInterface

	// interfaceManager 接口管理器
	interfaceManager *interfaces.Manager

	// arpTable ARP表
	arpTable *arp.ARPTable

	// running 运行状态
	running bool

	// mu 读写锁
	mu sync.RWMutex

	// 统计信息
	stats ForwardingStats

	// 配置参数
	config ForwardingConfig

	// 新增功能组件
	loadBalancer       *LoadBalancer
	failoverManager    *FailoverManager
	performanceMonitor *PerformanceMonitor
	trafficShaper      *TrafficShaper
	cache              *ForwardingCache

	// 工作队列
	packetQueue chan *IPPacket
	workerPool  []*PacketWorker
	workerCount int

	// 统计和监控
	metricsCollector *MetricsCollector
	alertManager     *AlertManager
}

type PacketWorker struct {
	id     int
	engine *ForwardingEngine
	queue  chan *IPPacket
	stop   chan struct{}
}

type MetricsCollector struct {
	mu       sync.RWMutex
	metrics  map[string]interface{}
	interval time.Duration
	stop     chan struct{}
}

type AlertManager struct {
	mu       sync.RWMutex
	rules    []AlertRule
	alerts   []Alert
	handlers []AlertHandler
	stop     chan struct{}
}

type AlertRule struct {
	ID        string
	Metric    string
	Operator  string
	Threshold interface{}
	Duration  time.Duration
	Level     AlertLevel
}

type AlertHandler interface {
	HandleAlert(alert Alert) error
	GetName() string
}

// 实现负载均衡功能
func NewLoadBalancer(algorithm LoadBalanceAlgorithm) *LoadBalancer {
	return &LoadBalancer{
		algorithm: algorithm,
		routes:    make([]RouteEntry, 0),
		weights:   make(map[string]int),
		counters:  make(map[string]uint64),
		health:    make(map[string]bool),
	}
}

func (lb *LoadBalancer) AddRoute(route routing.Route, weight int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	entry := RouteEntry{
		Route:     route,
		Weight:    weight,
		Health:    true,
		LastCheck: time.Now(),
	}

	lb.routes = append(lb.routes, entry)
	lb.weights[route.Interface] = weight
	lb.counters[route.Interface] = 0
	lb.health[route.Interface] = true
}

func (lb *LoadBalancer) SelectRoute(destination net.IP) (*RouteEntry, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	// 过滤健康的路由
	healthyRoutes := make([]RouteEntry, 0)
	for _, route := range lb.routes {
		if lb.health[route.Route.Interface] {
			healthyRoutes = append(healthyRoutes, route)
		}
	}

	if len(healthyRoutes) == 0 {
		return nil, fmt.Errorf("no healthy routes available")
	}

	switch lb.algorithm {
	case RoundRobin:
		return lb.selectRoundRobin(healthyRoutes)
	case WeightedRoundRobin:
		return lb.selectWeightedRoundRobin(healthyRoutes)
	case LeastConnections:
		return lb.selectLeastConnections(healthyRoutes)
	case IPHash:
		return lb.selectIPHash(healthyRoutes, destination)
	case Random:
		return lb.selectRandom(healthyRoutes)
	default:
		return &healthyRoutes[0], nil
	}
}

func (lb *LoadBalancer) selectRoundRobin(routes []RouteEntry) (*RouteEntry, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes available")
	}

	// 找到计数器最小的路由
	minCount := uint64(math.MaxUint64)
	var selectedRoute *RouteEntry

	for i := range routes {
		count := lb.counters[routes[i].Route.Interface]
		if count < minCount {
			minCount = count
			selectedRoute = &routes[i]
		}
	}

	if selectedRoute != nil {
		lb.counters[selectedRoute.Route.Interface]++
	}

	return selectedRoute, nil
}

func (lb *LoadBalancer) selectWeightedRoundRobin(routes []RouteEntry) (*RouteEntry, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes available")
	}

	// 计算加权轮询
	totalWeight := 0
	for _, route := range routes {
		totalWeight += route.Weight
	}

	if totalWeight == 0 {
		return &routes[0], nil
	}

	// 生成随机数
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	randNum := int(randBytes[0])<<24 | int(randBytes[1])<<16 | int(randBytes[2])<<8 | int(randBytes[3])
	if randNum < 0 {
		randNum = -randNum
	}
	target := randNum % totalWeight

	current := 0
	for i := range routes {
		current += routes[i].Weight
		if current > target {
			return &routes[i], nil
		}
	}

	return &routes[0], nil
}

func (lb *LoadBalancer) selectLeastConnections(routes []RouteEntry) (*RouteEntry, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes available")
	}

	minConnections := uint64(math.MaxUint64)
	var selectedRoute *RouteEntry

	for i := range routes {
		connections := lb.counters[routes[i].Route.Interface]
		if connections < minConnections {
			minConnections = connections
			selectedRoute = &routes[i]
		}
	}

	return selectedRoute, nil
}

func (lb *LoadBalancer) selectIPHash(routes []RouteEntry, destination net.IP) (*RouteEntry, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes available")
	}

	// 使用IP地址计算哈希
	hash := fnv.New32a()
	hash.Write(destination.To4())
	hashValue := hash.Sum32()

	index := int(hashValue) % len(routes)
	return &routes[index], nil
}

func (lb *LoadBalancer) selectRandom(routes []RouteEntry) (*RouteEntry, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes available")
	}

	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	randNum := int(randBytes[0])<<24 | int(randBytes[1])<<16 | int(randBytes[2])<<8 | int(randBytes[3])
	if randNum < 0 {
		randNum = -randNum
	}

	index := randNum % len(routes)
	return &routes[index], nil
}

func (lb *LoadBalancer) UpdateRouteHealth(routeInterface string, healthy bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.health[routeInterface] = healthy
}

// 实现故障切换功能
func NewFailoverManager() *FailoverManager {
	return &FailoverManager{
		primaryRoutes:   make(map[string]RouteEntry),
		backupRoutes:    make(map[string][]RouteEntry),
		healthCheckers:  make(map[string]*HealthChecker),
		failoverHistory: make(map[string][]FailoverEvent),
	}
}

func (fm *FailoverManager) AddPrimaryRoute(destination string, route RouteEntry) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.primaryRoutes[destination] = route

	// 启动健康检查
	checker := NewHealthChecker(route.Route.Gateway, 5*time.Second, 2*time.Second, 3)
	fm.healthCheckers[destination] = checker
	checker.Start()
}

func (fm *FailoverManager) AddBackupRoute(destination string, route RouteEntry) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if _, exists := fm.backupRoutes[destination]; !exists {
		fm.backupRoutes[destination] = make([]RouteEntry, 0)
	}

	fm.backupRoutes[destination] = append(fm.backupRoutes[destination], route)
}

func (fm *FailoverManager) GetActiveRoute(destination string) (*RouteEntry, error) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	// 检查主路由健康状态
	if primary, exists := fm.primaryRoutes[destination]; exists {
		if checker, ok := fm.healthCheckers[destination]; ok && checker.IsHealthy() {
			return &primary, nil
		}
	}

	// 主路由不可用，尝试备用路由
	if backups, exists := fm.backupRoutes[destination]; exists {
		for _, backup := range backups {
			if backup.Health {
				// 记录故障切换事件
				fm.recordFailoverEvent(destination, "FAILOVER", "Primary route unhealthy")
				return &backup, nil
			}
		}
	}

	return nil, fmt.Errorf("no healthy routes available for destination %s", destination)
}

func (fm *FailoverManager) recordFailoverEvent(destination, event, reason string) {
	failoverEvent := FailoverEvent{
		Timestamp: time.Now(),
		Route:     destination,
		Event:     event,
		Reason:    reason,
	}

	if _, exists := fm.failoverHistory[destination]; !exists {
		fm.failoverHistory[destination] = make([]FailoverEvent, 0)
	}

	fm.failoverHistory[destination] = append(fm.failoverHistory[destination], failoverEvent)

	// 保持历史记录在合理范围内
	if len(fm.failoverHistory[destination]) > 100 {
		fm.failoverHistory[destination] = fm.failoverHistory[destination][1:]
	}
}

// 实现健康检查
func NewHealthChecker(target net.IP, interval, timeout time.Duration, threshold int) *HealthChecker {
	return &HealthChecker{
		target:    target,
		interval:  interval,
		timeout:   timeout,
		threshold: threshold,
		failures:  0,
		isHealthy: true,
		stopChan:  make(chan struct{}),
		running:   false,
	}
}

func (hc *HealthChecker) Start() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if hc.running {
		return
	}

	hc.running = true
	go hc.healthCheckLoop()
}

func (hc *HealthChecker) Stop() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if !hc.running {
		return
	}

	hc.running = false
	close(hc.stopChan)
}

func (hc *HealthChecker) IsHealthy() bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	return hc.isHealthy
}

func (hc *HealthChecker) healthCheckLoop() {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.performHealthCheck()
		case <-hc.stopChan:
			return
		}
	}
}

func (hc *HealthChecker) performHealthCheck() {
	// 简化的健康检查：尝试连接目标
	conn, err := net.DialTimeout("tcp", hc.target.String()+":80", hc.timeout)

	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.lastCheck = time.Now()

	if err != nil {
		hc.failures++
		if hc.failures >= hc.threshold {
			hc.isHealthy = false
		}
	} else {
		if conn != nil {
			conn.Close()
		}
		hc.failures = 0
		hc.isHealthy = true
	}
}

// 实现性能监控
func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{
		metrics: make(map[string]*RouteMetrics),
		alertThresholds: AlertThresholds{
			MaxLatency:     100 * time.Millisecond,
			MaxPacketLoss:  0.05, // 5%
			MaxUtilization: 0.8,  // 80%
			MaxErrorRate:   0.01, // 1%
		},
		alerts:     make([]Alert, 0),
		collectors: make([]MetricCollector, 0),
	}
}

func (pm *PerformanceMonitor) UpdateMetrics(route string, metrics *RouteMetrics) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.metrics[route] = metrics

	// 检查告警阈值
	pm.checkAlerts(route, metrics)
}

func (pm *PerformanceMonitor) checkAlerts(route string, metrics *RouteMetrics) {
	// 检查延迟告警
	if metrics.Latency > pm.alertThresholds.MaxLatency {
		alert := Alert{
			ID:        fmt.Sprintf("latency_%s_%d", route, time.Now().Unix()),
			Timestamp: time.Now(),
			Level:     AlertWarning,
			Route:     route,
			Metric:    "latency",
			Value:     metrics.Latency,
			Threshold: pm.alertThresholds.MaxLatency,
			Message:   fmt.Sprintf("High latency on route %s: %v", route, metrics.Latency),
		}
		pm.alerts = append(pm.alerts, alert)
	}

	// 检查丢包率告警
	if metrics.PacketLoss > pm.alertThresholds.MaxPacketLoss {
		alert := Alert{
			ID:        fmt.Sprintf("packetloss_%s_%d", route, time.Now().Unix()),
			Timestamp: time.Now(),
			Level:     AlertCritical,
			Route:     route,
			Metric:    "packet_loss",
			Value:     metrics.PacketLoss,
			Threshold: pm.alertThresholds.MaxPacketLoss,
			Message:   fmt.Sprintf("High packet loss on route %s: %.2f%%", route, metrics.PacketLoss*100),
		}
		pm.alerts = append(pm.alerts, alert)
	}

	// 检查利用率告警
	if metrics.Utilization > pm.alertThresholds.MaxUtilization {
		alert := Alert{
			ID:        fmt.Sprintf("utilization_%s_%d", route, time.Now().Unix()),
			Timestamp: time.Now(),
			Level:     AlertWarning,
			Route:     route,
			Metric:    "utilization",
			Value:     metrics.Utilization,
			Threshold: pm.alertThresholds.MaxUtilization,
			Message:   fmt.Sprintf("High utilization on route %s: %.2f%%", route, metrics.Utilization*100),
		}
		pm.alerts = append(pm.alerts, alert)
	}
}

func (pm *PerformanceMonitor) GetMetrics(route string) (*RouteMetrics, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	metrics, exists := pm.metrics[route]
	return metrics, exists
}

func (pm *PerformanceMonitor) GetAllMetrics() map[string]*RouteMetrics {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make(map[string]*RouteMetrics)
	for k, v := range pm.metrics {
		result[k] = v
	}
	return result
}

func (pm *PerformanceMonitor) GetAlerts() []Alert {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return append([]Alert(nil), pm.alerts...)
}

// 实现流量整形
func NewTrafficShaper() *TrafficShaper {
	return &TrafficShaper{
		policies: make(map[string]*ShapingPolicy),
		buckets:  make(map[string]*TokenBucket),
		queues:   make(map[string]*PriorityQueue),
	}
}

func (ts *TrafficShaper) AddPolicy(route string, policy *ShapingPolicy) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.policies[route] = policy
	ts.buckets[route] = NewTokenBucket(float64(policy.Rate), float64(policy.BurstSize))
	ts.queues[route] = NewPriorityQueue(1000) // 最大1000个数据包
}

func (ts *TrafficShaper) ShapePacket(route string, packet *IPPacket) bool {
	ts.mu.RLock()
	policy, exists := ts.policies[route]
	bucket, bucketExists := ts.buckets[route]
	queue, queueExists := ts.queues[route]
	ts.mu.RUnlock()

	if !exists || !bucketExists || !queueExists {
		return true // 没有策略，直接通过
	}

	// 检查令牌桶
	if bucket.TakeTokens(float64(packet.Size)) {
		return true // 有足够令牌，直接发送
	}

	// 没有足够令牌，加入队列
	queuedPacket := &QueuedPacket{
		Packet:    packet,
		Priority:  policy.Priority,
		Timestamp: time.Now(),
		Size:      packet.Size,
	}

	return queue.Enqueue(queuedPacket)
}

// 实现令牌桶
func NewTokenBucket(rate, capacity float64) *TokenBucket {
	return &TokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		rate:       rate,
		lastUpdate: time.Now(),
	}
}

func (tb *TokenBucket) TakeTokens(tokens float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()

	// 添加新令牌
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	tb.lastUpdate = now

	if tb.tokens >= tokens {
		tb.tokens -= tokens
		return true
	}

	return false
}

// 实现优先级队列
func NewPriorityQueue(maxSize int) *PriorityQueue {
	pq := &PriorityQueue{
		maxSize: maxSize,
	}

	// 初始化权重（优先级越低，权重越高）
	for i := 0; i < 8; i++ {
		pq.weights[i] = 8 - i
	}

	return pq
}

func (pq *PriorityQueue) Enqueue(packet *QueuedPacket) bool {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	priority := packet.Priority
	if priority < 0 || priority >= 8 {
		priority = 7 // 默认最低优先级
	}

	// 检查队列是否已满
	totalSize := 0
	for i := 0; i < 8; i++ {
		totalSize += pq.sizes[i]
	}

	if totalSize >= pq.maxSize {
		// 队列已满，根据丢弃策略处理
		return false
	}

	pq.queues[priority] = append(pq.queues[priority], packet)
	pq.sizes[priority]++

	return true
}

func (pq *PriorityQueue) Dequeue() *QueuedPacket {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// 按优先级顺序检查队列
	for i := 0; i < 8; i++ {
		if pq.sizes[i] > 0 {
			packet := pq.queues[i][0]
			pq.queues[i] = pq.queues[i][1:]
			pq.sizes[i]--
			return packet
		}
	}

	return nil
}

// 实现转发缓存
func NewForwardingCache(maxSize int, ttl time.Duration) *ForwardingCache {
	return &ForwardingCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
		lru:     NewLRUCache(maxSize),
	}
}

func (fc *ForwardingCache) Get(destination net.IP) (*CacheEntry, bool) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	key := destination.String()
	entry, exists := fc.entries[key]

	if !exists {
		return nil, false
	}

	// 检查是否过期
	if time.Since(entry.Timestamp) > fc.ttl {
		delete(fc.entries, key)
		fc.lru.Remove(key)
		return nil, false
	}

	// 更新LRU
	fc.lru.Get(key)
	entry.HitCount++

	return entry, true
}

func (fc *ForwardingCache) Put(destination net.IP, route routing.Route, nextHop net.IP, iface string, mac net.HardwareAddr) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	key := destination.String()
	entry := &CacheEntry{
		Route:     route,
		NextHop:   nextHop,
		Interface: iface,
		MAC:       mac,
		Timestamp: time.Now(),
		HitCount:  0,
	}

	// 检查缓存大小
	if len(fc.entries) >= fc.maxSize {
		// 移除LRU条目
		oldestKey := fc.lru.RemoveLRU()
		if oldestKey != "" {
			delete(fc.entries, oldestKey)
		}
	}

	fc.entries[key] = entry
	fc.lru.Put(key, entry)
}

// 实现LRU缓存
func NewLRUCache(capacity int) *LRUCache {
	lru := &LRUCache{
		capacity: capacity,
		items:    make(map[string]*LRUNode),
	}

	// 创建哨兵节点
	lru.head = &LRUNode{}
	lru.tail = &LRUNode{}
	lru.head.next = lru.tail
	lru.tail.prev = lru.head

	return lru
}

func (lru *LRUCache) Get(key string) *CacheEntry {
	if node, exists := lru.items[key]; exists {
		lru.moveToHead(node)
		return node.value
	}
	return nil
}

func (lru *LRUCache) Put(key string, value *CacheEntry) {
	if node, exists := lru.items[key]; exists {
		node.value = value
		lru.moveToHead(node)
	} else {
		newNode := &LRUNode{
			key:   key,
			value: value,
		}

		if len(lru.items) >= lru.capacity {
			tail := lru.removeTail()
			delete(lru.items, tail.key)
		}

		lru.items[key] = newNode
		lru.addToHead(newNode)
	}
}

func (lru *LRUCache) Remove(key string) {
	if node, exists := lru.items[key]; exists {
		lru.removeNode(node)
		delete(lru.items, key)
	}
}

func (lru *LRUCache) RemoveLRU() string {
	tail := lru.removeTail()
	if tail != nil {
		delete(lru.items, tail.key)
		return tail.key
	}
	return ""
}

func (lru *LRUCache) addToHead(node *LRUNode) {
	node.prev = lru.head
	node.next = lru.head.next
	lru.head.next.prev = node
	lru.head.next = node
}

func (lru *LRUCache) removeNode(node *LRUNode) {
	node.prev.next = node.next
	node.next.prev = node.prev
}

func (lru *LRUCache) moveToHead(node *LRUNode) {
	lru.removeNode(node)
	lru.addToHead(node)
}

func (lru *LRUCache) removeTail() *LRUNode {
	lastNode := lru.tail.prev
	if lastNode == lru.head {
		return nil
	}
	lru.removeNode(lastNode)
	return lastNode
}

// 实现数据包分发器
func (fe *ForwardingEngine) packetDispatcher() {
	for {
		select {
		case packet := <-fe.packetQueue:
			if !fe.IsRunning() {
				return
			}

			// 选择工作线程（简单的轮询）
			workerIndex := int(atomic.AddUint64(&fe.stats.PacketsReceived, 1)) % fe.workerCount

			select {
			case fe.workerPool[workerIndex].queue <- packet:
				// 成功分发
			default:
				// 工作线程队列已满，丢弃数据包
				atomic.AddUint64(&fe.stats.PacketsDropped, 1)
			}
		}
	}
}

// 实现工作线程
func (pw *PacketWorker) Start() {
	for {
		select {
		case packet := <-pw.queue:
			pw.engine.processPacket(packet)
		case <-pw.stop:
			return
		}
	}
}

func (pw *PacketWorker) Stop() {
	close(pw.stop)
}

// 实现增强的数据包处理
func (fe *ForwardingEngine) processPacket(pkt *IPPacket) {
	start := time.Now()

	// 检查缓存
	if entry, found := fe.cache.Get(pkt.Destination); found {
		fe.forwardFromCache(pkt, entry)
		return
	}

	// 使用负载均衡选择路由
	routeEntry, err := fe.loadBalancer.SelectRoute(pkt.Destination)
	if err != nil {
		// 尝试故障切换
		routeEntry, err = fe.failoverManager.GetActiveRoute(pkt.Destination.String())
		if err != nil {
			atomic.AddUint64(&fe.stats.PacketsDropped, 1)
			return
		}
	}

	// 应用流量整形
	if !fe.trafficShaper.ShapePacket(routeEntry.Route.Interface, pkt) {
		atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		return
	}

	// 执行转发
	err = fe.ForwardPacket(pkt)
	if err != nil {
		atomic.AddUint64(&fe.stats.PacketsDropped, 1)
	} else {
		atomic.AddUint64(&fe.stats.PacketsForwarded, 1)

		// 更新缓存
		// 这里需要从实际转发过程中获取下一跳和MAC地址
		// 简化实现，假设我们有这些信息
		fe.cache.Put(pkt.Destination, routeEntry.Route, routeEntry.Route.Gateway, routeEntry.Route.Interface, nil)
	}

	// 更新性能指标
	latency := time.Since(start)
	metrics := &RouteMetrics{
		PacketsForwarded: 1,
		BytesForwarded:   uint64(pkt.Size),
		Latency:          latency,
		LastUpdate:       time.Now(),
	}
	fe.performanceMonitor.UpdateMetrics(routeEntry.Route.Interface, metrics)
}

func (fe *ForwardingEngine) forwardFromCache(pkt *IPPacket, entry *CacheEntry) {
	// 从缓存转发数据包
	atomic.AddUint64(&fe.stats.PacketsForwarded, 1)

	// 更新缓存命中统计
	entry.HitCount++
}

// 实现指标收集器
func NewMetricsCollector(interval time.Duration) *MetricsCollector {
	return &MetricsCollector{
		metrics:  make(map[string]interface{}),
		interval: interval,
		stop:     make(chan struct{}),
	}
}

func (mc *MetricsCollector) Start() {
	ticker := time.NewTicker(mc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.collectMetrics()
		case <-mc.stop:
			return
		}
	}
}

func (mc *MetricsCollector) Stop() {
	close(mc.stop)
}

func (mc *MetricsCollector) collectMetrics() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// 收集系统指标
	mc.metrics["timestamp"] = time.Now()
	mc.metrics["cpu_usage"] = mc.getCPUUsage()
	mc.metrics["memory_usage"] = mc.getMemoryUsage()
	mc.metrics["network_io"] = mc.getNetworkIO()
}

func (mc *MetricsCollector) getCPUUsage() float64 {
	// 简单的CPU使用率模拟
	return 0.1 + (float64(time.Now().UnixNano()%100) / 1000.0)
}

func (mc *MetricsCollector) getMemoryUsage() float64 {
	// 简单的内存使用率模拟
	return 0.2 + (float64(time.Now().UnixNano()%200) / 2000.0)
}

func (mc *MetricsCollector) getNetworkIO() map[string]uint64 {
	// 简单的网络IO模拟
	return map[string]uint64{
		"bytes_in":  uint64(time.Now().UnixNano() % 1000000),
		"bytes_out": uint64(time.Now().UnixNano() % 1000000),
	}
}

// 实现告警管理器
func NewAlertManager() *AlertManager {
	return &AlertManager{
		rules:    make([]AlertRule, 0),
		alerts:   make([]Alert, 0),
		handlers: make([]AlertHandler, 0),
		stop:     make(chan struct{}),
	}
}

func (am *AlertManager) Start() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.evaluateRules()
		case <-am.stop:
			return
		}
	}
}

func (am *AlertManager) Stop() {
	close(am.stop)
}

func (am *AlertManager) evaluateRules() {
	am.mu.Lock()
	defer am.mu.Unlock()

	// 评估告警规则
	for _, rule := range am.rules {
		if am.shouldTriggerAlert(rule) {
			alert := Alert{
				ID:        fmt.Sprintf("%s_%d", rule.ID, time.Now().Unix()),
				Timestamp: time.Now(),
				Level:     rule.Level,
				Message:   fmt.Sprintf("Alert rule %s triggered", rule.ID),
			}
			am.alerts = append(am.alerts, alert)
			am.handleAlert(alert)
		}
	}
}

func (am *AlertManager) shouldTriggerAlert(rule AlertRule) bool {
	// 简单的告警触发逻辑
	return false
}

func (am *AlertManager) handleAlert(alert Alert) {
	for _, handler := range am.handlers {
		handler.HandleAlert(alert)
	}
}

// 添加高级转发方法
func (fe *ForwardingEngine) ForwardPacketAsync(pkt *IPPacket) error {
	if !fe.IsRunning() {
		return fmt.Errorf("转发引擎未运行")
	}

	select {
	case fe.packetQueue <- pkt:
		return nil
	default:
		atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		return fmt.Errorf("数据包队列已满")
	}
}

func (fe *ForwardingEngine) GetAdvancedStats() map[string]interface{} {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	stats := make(map[string]interface{})

	// 基本统计
	stats["packets_received"] = atomic.LoadUint64(&fe.stats.PacketsReceived)
	stats["packets_forwarded"] = atomic.LoadUint64(&fe.stats.PacketsForwarded)
	stats["packets_dropped"] = atomic.LoadUint64(&fe.stats.PacketsDropped)

	// 缓存统计
	cacheStats := make(map[string]interface{})
	cacheStats["entries"] = len(fe.cache.entries)
	cacheStats["hit_rate"] = fe.calculateCacheHitRate()
	stats["cache"] = cacheStats

	// 负载均衡统计
	lbStats := make(map[string]interface{})
	lbStats["algorithm"] = fe.loadBalancer.algorithm
	lbStats["routes"] = len(fe.loadBalancer.routes)
	stats["load_balancer"] = lbStats

	// 性能监控统计
	stats["performance"] = fe.performanceMonitor.GetAllMetrics()

	// 告警统计
	stats["alerts"] = len(fe.alertManager.alerts)

	return stats
}

func (fe *ForwardingEngine) calculateCacheHitRate() float64 {
	totalHits := uint64(0)
	totalRequests := uint64(0)

	for _, entry := range fe.cache.entries {
		totalHits += entry.HitCount
		totalRequests += entry.HitCount + 1 // +1 for the miss that created the entry
	}

	if totalRequests == 0 {
		return 0.0
	}

	return float64(totalHits) / float64(totalRequests)
}
