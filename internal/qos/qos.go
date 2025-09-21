package qos

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Engine QoS流量控制引擎
// 提供流量整形、带宽限制、优先级控制等功能
//
// 主要功能：
// 1. 流量分类：基于规则对流量进行分类
// 2. 带宽限制：限制特定流量的带宽使用
// 3. 优先级控制：为不同类型流量设置优先级
// 4. 流量整形：平滑突发流量，避免网络拥塞
// 5. 队列管理：实现多种队列调度算法
//
// 支持的QoS算法：
// - Token Bucket：令牌桶算法，用于流量整形
// - Leaky Bucket：漏桶算法，用于流量平滑
// - Priority Queue：优先级队列调度
// - Weighted Fair Queue：加权公平队列
// - Class-Based Queue：基于类别的队列管理
//
// 流量分类支持：
// - 基于IP地址和端口的分类
// - 基于协议类型的分类
// - 基于DSCP标记的分类
// - 基于应用层协议的分类
// - 自定义规则分类
type Engine struct {
	// mu 读写锁
	mu sync.RWMutex

	// running 运行状态
	running bool

	// 流量分类器
	classifier *TrafficClassifier

	// 队列管理器
	queueManager *QueueManager

	// 流量整形器
	shapers map[string]*TrafficShaper

	// 带宽限制器
	limiters map[string]*BandwidthLimiter

	// 统计信息
	stats Stats

	// 配置参数
	config Config
}

// TrafficClassifier 流量分类器
type TrafficClassifier struct {
	// mu 读写锁
	mu sync.RWMutex

	// rules 分类规则
	rules []ClassificationRule

	// defaultClass 默认流量类别
	defaultClass string
}

// ClassificationRule 流量分类规则
type ClassificationRule struct {
	// ID 规则ID
	ID string

	// Name 规则名称
	Name string

	// Priority 优先级（数字越小优先级越高）
	Priority int

	// SourceIP 源IP地址/网络
	SourceIP *net.IPNet

	// DestIP 目标IP地址/网络
	DestIP *net.IPNet

	// SourcePort 源端口范围
	SourcePort PortRange

	// DestPort 目标端口范围
	DestPort PortRange

	// Protocol 协议类型
	Protocol string

	// DSCP DSCP标记
	DSCP int

	// Application 应用类型
	Application string

	// TrafficClass 流量类别
	TrafficClass string

	// Enabled 是否启用
	Enabled bool

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

// QueueManager 队列管理器
type QueueManager struct {
	// mu 读写锁
	mu sync.RWMutex

	// queues 队列映射
	queues map[string]*TrafficQueue

	// scheduler 调度器
	scheduler QueueScheduler

	// maxQueues 最大队列数
	maxQueues int
}

// TrafficQueue 流量队列
type TrafficQueue struct {
	// ID 队列ID
	ID string

	// Name 队列名称
	Name string

	// Class 流量类别
	Class string

	// Priority 优先级
	Priority int

	// MaxBandwidth 最大带宽（bps）
	MaxBandwidth uint64

	// MinBandwidth 最小保证带宽（bps）
	MinBandwidth uint64

	// MaxPackets 最大包数
	MaxPackets int

	// MaxBytes 最大字节数
	MaxBytes uint64

	// packets 数据包队列
	packets []*QueuedPacket

	// currentBytes 当前字节数
	currentBytes uint64

	// stats 队列统计
	stats QueueStats

	// shaper 流量整形器
	shaper *TrafficShaper

	// limiter 带宽限制器
	limiter *BandwidthLimiter

	// CreatedAt 创建时间
	CreatedAt time.Time
}

// QueuedPacket 队列中的数据包
type QueuedPacket struct {
	// Data 数据包内容
	Data []byte

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

	// Priority 优先级
	Priority int

	// DSCP DSCP标记
	DSCP int

	// EnqueueTime 入队时间
	EnqueueTime time.Time

	// Class 流量类别
	Class string
}

// QueueScheduler 队列调度器接口
type QueueScheduler interface {
	// Schedule 调度队列，返回下一个要处理的队列ID
	Schedule(queues map[string]*TrafficQueue) string

	// UpdateWeights 更新队列权重
	UpdateWeights(weights map[string]int)
}

// PriorityScheduler 优先级调度器
type PriorityScheduler struct {
	// weights 队列权重
	weights map[string]int
}

// WeightedFairScheduler 加权公平调度器
type WeightedFairScheduler struct {
	// weights 队列权重
	weights map[string]int

	// virtualTime 虚拟时间
	virtualTime map[string]uint64
}

// TrafficShaper 流量整形器
type TrafficShaper struct {
	// mu 读写锁
	mu sync.RWMutex

	// algorithm 整形算法 (token_bucket, leaky_bucket)
	algorithm string

	// rate 速率限制（bps）
	rate uint64

	// burstSize 突发大小（bytes）
	burstSize uint64

	// tokens 当前令牌数
	tokens uint64

	// lastUpdate 最后更新时间
	lastUpdate time.Time

	// stats 统计信息
	stats ShaperStats
}

// BandwidthLimiter 带宽限制器
type BandwidthLimiter struct {
	// mu 读写锁
	mu sync.RWMutex

	// maxBandwidth 最大带宽（bps）
	maxBandwidth uint64

	// currentUsage 当前使用量（bps）
	currentUsage uint64

	// window 统计窗口
	window time.Duration

	// samples 采样数据
	samples []BandwidthSample

	// stats 统计信息
	stats LimiterStats
}

// BandwidthSample 带宽采样
type BandwidthSample struct {
	// Timestamp 时间戳
	Timestamp time.Time

	// Bytes 字节数
	Bytes uint64
}

// Stats QoS统计信息
type Stats struct {
	// PacketsProcessed 处理的数据包总数
	PacketsProcessed uint64

	// PacketsDropped 丢弃的数据包数
	PacketsDropped uint64

	// PacketsDelayed 延迟的数据包数
	PacketsDelayed uint64

	// BytesProcessed 处理的字节总数
	BytesProcessed uint64

	// BytesDropped 丢弃的字节数
	BytesDropped uint64

	// AverageLatency 平均延迟
	AverageLatency time.Duration

	// QueueStats 队列统计
	QueueStats map[string]QueueStats

	// ClassStats 类别统计
	ClassStats map[string]ClassStats

	// StartTime 统计开始时间
	StartTime time.Time
}

// QueueStats 队列统计信息
type QueueStats struct {
	// PacketsEnqueued 入队数据包数
	PacketsEnqueued uint64

	// PacketsDequeued 出队数据包数
	PacketsDequeued uint64

	// PacketsDropped 丢弃数据包数
	PacketsDropped uint64

	// BytesEnqueued 入队字节数
	BytesEnqueued uint64

	// BytesDequeued 出队字节数
	BytesDequeued uint64

	// CurrentPackets 当前队列包数
	CurrentPackets int

	// CurrentBytes 当前队列字节数
	CurrentBytes uint64

	// AverageDelay 平均延迟
	AverageDelay time.Duration

	// MaxDelay 最大延迟
	MaxDelay time.Duration
}

// ClassStats 类别统计信息
type ClassStats struct {
	// PacketsClassified 分类的数据包数
	PacketsClassified uint64

	// BytesClassified 分类的字节数
	BytesClassified uint64

	// AverageBandwidth 平均带宽使用
	AverageBandwidth uint64

	// PeakBandwidth 峰值带宽使用
	PeakBandwidth uint64
}

// ShaperStats 整形器统计信息
type ShaperStats struct {
	// PacketsShaped 整形的数据包数
	PacketsShaped uint64

	// PacketsDropped 丢弃的数据包数
	PacketsDropped uint64

	// BytesShaped 整形的字节数
	BytesShaped uint64

	// TokensGenerated 生成的令牌数
	TokensGenerated uint64

	// TokensConsumed 消耗的令牌数
	TokensConsumed uint64
}

// LimiterStats 限制器统计信息
type LimiterStats struct {
	// PacketsLimited 限制的数据包数
	PacketsLimited uint64

	// PacketsDropped 丢弃的数据包数
	PacketsDropped uint64

	// BytesLimited 限制的字节数
	BytesLimited uint64

	// CurrentBandwidth 当前带宽使用
	CurrentBandwidth uint64

	// PeakBandwidth 峰值带宽使用
	PeakBandwidth uint64
}

// Config QoS配置
type Config struct {
	// Enabled 是否启用QoS
	Enabled bool

	// DefaultClass 默认流量类别
	DefaultClass string

	// MaxQueues 最大队列数
	MaxQueues int

	// DefaultQueueSize 默认队列大小
	DefaultQueueSize int

	// SchedulerType 调度器类型 (priority, weighted_fair)
	SchedulerType string

	// StatsInterval 统计间隔
	StatsInterval time.Duration

	// CleanupInterval 清理间隔
	CleanupInterval time.Duration
}

// NewQoSEngine 创建新的QoS引擎
//
// 返回值：
//   - *Engine: QoS引擎实例
//
// 使用示例：
//
//	qos := NewQoSEngine()
//	qos.Start()
//	defer qos.Stop()
//
//	// 添加流量分类规则
//	rule := ClassificationRule{
//	    ID: "web-traffic",
//	    Protocol: "tcp",
//	    DestPort: PortRange{Start: 80, End: 80},
//	    TrafficClass: "web",
//	}
//	qos.AddClassificationRule(rule)
//
//	// 创建队列
//	queue := &TrafficQueue{
//	    ID: "web-queue",
//	    Class: "web",
//	    Priority: 1,
//	    MaxBandwidth: 10 * 1024 * 1024, // 10 Mbps
//	}
//	qos.CreateQueue(queue)
func NewQoSEngine() *Engine {
	qos := &Engine{
		running:  false,
		shapers:  make(map[string]*TrafficShaper),
		limiters: make(map[string]*BandwidthLimiter),
		stats: Stats{
			QueueStats: make(map[string]QueueStats),
			ClassStats: make(map[string]ClassStats),
			StartTime:  time.Now(),
		},
		config: Config{
			Enabled:          true,
			DefaultClass:     "default",
			MaxQueues:        100,
			DefaultQueueSize: 1000,
			SchedulerType:    "priority",
			StatsInterval:    10 * time.Second,
			CleanupInterval:  60 * time.Second,
		},
	}

	// 初始化流量分类器
	qos.classifier = &TrafficClassifier{
		rules:        make([]ClassificationRule, 0),
		defaultClass: qos.config.DefaultClass,
	}

	// 初始化队列管理器
	qos.queueManager = &QueueManager{
		queues:    make(map[string]*TrafficQueue),
		maxQueues: qos.config.MaxQueues,
	}

	// 根据配置创建调度器
	switch qos.config.SchedulerType {
	case "priority":
		qos.queueManager.scheduler = &PriorityScheduler{
			weights: make(map[string]int),
		}
	case "weighted_fair":
		qos.queueManager.scheduler = &WeightedFairScheduler{
			weights:     make(map[string]int),
			virtualTime: make(map[string]uint64),
		}
	default:
		qos.queueManager.scheduler = &PriorityScheduler{
			weights: make(map[string]int),
		}
	}

	return qos
}

// Start 启动QoS引擎
func (qos *Engine) Start() error {
	qos.mu.Lock()
	defer qos.mu.Unlock()

	if qos.running {
		return fmt.Errorf("QoS引擎已经在运行")
	}

	qos.running = true
	qos.stats.StartTime = time.Now()

	// 启动统计协程
	go qos.statsWorker()

	// 启动清理协程
	go qos.cleanupWorker()

	// 启动队列处理协程
	go qos.queueProcessor()

	// 启动自适应QoS（如果配置启用）
	if qos.config.Enabled {
		adaptiveQoS := NewAdaptiveQoS(qos)
		go adaptiveQoS.Start()
	}

	return nil
}

// Stop 停止QoS引擎
func (qos *Engine) Stop() {
	qos.mu.Lock()
	defer qos.mu.Unlock()

	qos.running = false
}

// ProcessPacket 处理数据包
// 这是QoS引擎的核心方法，对数据包进行分类、入队和调度
//
// 处理流程：
// 1. 流量分类：根据规则对数据包进行分类
// 2. 队列选择：选择合适的队列进行入队
// 3. 流量整形：应用流量整形策略
// 4. 带宽限制：检查带宽限制
// 5. 入队操作：将数据包加入队列
//
// 参数：
//   - packet: 数据包信息
//
// 返回值：
//   - bool: 是否成功处理（true表示入队成功，false表示被丢弃）
//   - error: 处理错误
func (qos *Engine) ProcessPacket(packet *QueuedPacket) (bool, error) {
	if !qos.IsRunning() {
		return false, fmt.Errorf("QoS引擎未运行")
	}

	// 更新统计信息
	qos.mu.Lock()
	qos.stats.PacketsProcessed++
	qos.stats.BytesProcessed += uint64(packet.Size)
	qos.mu.Unlock()

	// 第一步：流量分类
	class := qos.classifyPacket(packet)
	packet.Class = class

	// 第二步：选择队列
	queueID := qos.selectQueue(class)
	if queueID == "" {
		// 没有合适的队列，丢弃数据包
		qos.updateDropStats(packet)
		return false, fmt.Errorf("没有可用的队列")
	}

	// 第三步：获取队列
	queue, exists := qos.getQueue(queueID)
	if !exists {
		qos.updateDropStats(packet)
		return false, fmt.Errorf("队列不存在: %s", queueID)
	}

	// 第四步：流量整形检查
	if queue.shaper != nil {
		allowed := queue.shaper.AllowPacket(packet.Size)
		if !allowed {
			qos.updateDropStats(packet)
			return false, fmt.Errorf("流量整形限制")
		}
	}

	// 第五步：带宽限制检查
	if queue.limiter != nil {
		allowed := queue.limiter.AllowPacket(packet.Size)
		if !allowed {
			qos.updateDropStats(packet)
			return false, fmt.Errorf("带宽限制")
		}
	}

	// 第六步：入队
	success := qos.enqueuePacket(queue, packet)
	if !success {
		qos.updateDropStats(packet)
		return false, fmt.Errorf("队列已满")
	}

	return true, nil
}

// classifyPacket 对数据包进行分类
func (qos *Engine) classifyPacket(packet *QueuedPacket) string {
	qos.classifier.mu.RLock()
	defer qos.classifier.mu.RUnlock()

	// 按优先级排序规则
	rules := make([]ClassificationRule, len(qos.classifier.rules))
	copy(rules, qos.classifier.rules)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	// 匹配规则
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if qos.ruleMatches(&rule, packet) {
			// 更新规则命中统计
			qos.classifier.mu.RUnlock()
			qos.classifier.mu.Lock()
			rule.HitCount++
			qos.classifier.mu.Unlock()
			qos.classifier.mu.RLock()

			// 更新类别统计
			qos.updateClassStats(rule.TrafficClass, packet)

			return rule.TrafficClass
		}
	}

	// 没有匹配的规则，使用默认类别
	qos.updateClassStats(qos.classifier.defaultClass, packet)
	return qos.classifier.defaultClass
}

// ruleMatches 检查规则是否匹配数据包
func (qos *Engine) ruleMatches(rule *ClassificationRule, packet *QueuedPacket) bool {
	// 检查协议
	if rule.Protocol != "" && rule.Protocol != "all" && rule.Protocol != packet.Protocol {
		return false
	}

	// 检查源IP
	if rule.SourceIP != nil && !rule.SourceIP.Contains(packet.SourceIP) {
		return false
	}

	// 检查目标IP
	if rule.DestIP != nil && !rule.DestIP.Contains(packet.DestIP) {
		return false
	}

	// 检查源端口
	if rule.SourcePort.Start > 0 && !qos.portInRange(packet.SourcePort, rule.SourcePort) {
		return false
	}

	// 检查目标端口
	if rule.DestPort.Start > 0 && !qos.portInRange(packet.DestPort, rule.DestPort) {
		return false
	}

	// 检查DSCP
	if rule.DSCP > 0 && rule.DSCP != packet.DSCP {
		return false
	}

	return true
}

// portInRange 检查端口是否在范围内
func (qos *Engine) portInRange(port int, portRange PortRange) bool {
	if portRange.End == 0 {
		portRange.End = portRange.Start
	}
	return port >= portRange.Start && port <= portRange.End
}

// selectQueue 选择队列
func (qos *Engine) selectQueue(class string) string {
	qos.queueManager.mu.RLock()
	defer qos.queueManager.mu.RUnlock()

	// 查找匹配类别的队列
	for queueID, queue := range qos.queueManager.queues {
		if queue.Class == class {
			return queueID
		}
	}

	// 查找默认队列
	for queueID, queue := range qos.queueManager.queues {
		if queue.Class == qos.config.DefaultClass {
			return queueID
		}
	}

	return ""
}

// getQueue 获取队列
func (qos *Engine) getQueue(queueID string) (*TrafficQueue, bool) {
	qos.queueManager.mu.RLock()
	defer qos.queueManager.mu.RUnlock()

	queue, exists := qos.queueManager.queues[queueID]
	return queue, exists
}

// enqueuePacket 将数据包入队
func (qos *Engine) enqueuePacket(queue *TrafficQueue, packet *QueuedPacket) bool {
	// 检查队列容量
	if len(queue.packets) >= queue.MaxPackets {
		return false
	}

	if queue.currentBytes+uint64(packet.Size) > queue.MaxBytes {
		return false
	}

	// 设置入队时间
	packet.EnqueueTime = time.Now()

	// 入队
	queue.packets = append(queue.packets, packet)
	queue.currentBytes += uint64(packet.Size)

	// 更新队列统计
	queue.stats.PacketsEnqueued++
	queue.stats.BytesEnqueued += uint64(packet.Size)
	queue.stats.CurrentPackets = len(queue.packets)
	queue.stats.CurrentBytes = queue.currentBytes

	return true
}

// updateDropStats 更新丢包统计
func (qos *Engine) updateDropStats(packet *QueuedPacket) {
	qos.mu.Lock()
	defer qos.mu.Unlock()

	qos.stats.PacketsDropped++
	qos.stats.BytesDropped += uint64(packet.Size)
}

// updateClassStats 更新类别统计
func (qos *Engine) updateClassStats(class string, packet *QueuedPacket) {
	qos.mu.Lock()
	defer qos.mu.Unlock()

	stats, exists := qos.stats.ClassStats[class]
	if !exists {
		stats = ClassStats{}
	}

	stats.PacketsClassified++
	stats.BytesClassified += uint64(packet.Size)

	qos.stats.ClassStats[class] = stats
}

// queueProcessor 队列处理器
func (qos *Engine) queueProcessor() {
	ticker := time.NewTicker(1 * time.Millisecond) // 高频处理
	defer ticker.Stop()

	for qos.IsRunning() {
		<-ticker.C
		qos.processQueues()
	}
}

// processQueues 处理队列
func (qos *Engine) processQueues() {
	// 使用调度器选择下一个要处理的队列
	queueID := qos.queueManager.scheduler.Schedule(qos.queueManager.queues)
	if queueID == "" {
		return
	}

	queue, exists := qos.getQueue(queueID)
	if !exists || len(queue.packets) == 0 {
		return
	}

	// 出队数据包
	packet := queue.packets[0]
	queue.packets = queue.packets[1:]
	queue.currentBytes -= uint64(packet.Size)

	// 更新队列统计
	queue.stats.PacketsDequeued++
	queue.stats.BytesDequeued += uint64(packet.Size)
	queue.stats.CurrentPackets = len(queue.packets)
	queue.stats.CurrentBytes = queue.currentBytes

	// 计算延迟
	delay := time.Since(packet.EnqueueTime)
	if delay > queue.stats.MaxDelay {
		queue.stats.MaxDelay = delay
	}

	// 这里应该将数据包发送到网络接口
	// 当前为模拟实现
	qos.sendPacket(packet)
}

// sendPacket 发送数据包
func (qos *Engine) sendPacket(packet *QueuedPacket) {
	// 记录发送开始时间
	sendStart := time.Now()

	// 应用流量整形
	if queue, exists := qos.queueManager.queues[packet.Class]; exists && queue.shaper != nil {
		if !queue.shaper.AllowPacket(packet.Size) {
			// 数据包被流量整形器丢弃
			qos.stats.PacketsDropped++
			qos.stats.BytesDropped += uint64(packet.Size)
			return
		}
	}

	// 应用带宽限制
	if queue, exists := qos.queueManager.queues[packet.Class]; exists && queue.limiter != nil {
		if !queue.limiter.AllowPacket(packet.Size) {
			// 数据包被带宽限制器丢弃
			qos.stats.PacketsDropped++
			qos.stats.BytesDropped += uint64(packet.Size)
			return
		}
	}

	// 实际发送逻辑（这里可以集成到网络接口）
	err := qos.performNetworkSend(packet)
	if err != nil {
		// 发送失败，更新统计信息
		qos.stats.PacketsDropped++
		qos.stats.BytesDropped += uint64(packet.Size)
		return
	}

	// 更新发送统计信息
	sendDuration := time.Since(sendStart)
	qos.stats.PacketsProcessed++
	qos.stats.BytesProcessed += uint64(packet.Size)

	// 更新平均延迟
	if qos.stats.PacketsProcessed == 1 {
		qos.stats.AverageLatency = sendDuration
	} else {
		// 计算移动平均
		qos.stats.AverageLatency = (qos.stats.AverageLatency*time.Duration(qos.stats.PacketsProcessed-1) + sendDuration) / time.Duration(qos.stats.PacketsProcessed)
	}
}

// performNetworkSend 执行实际的网络发送
func (qos *Engine) performNetworkSend(packet *QueuedPacket) error {
	// 在真实环境中，这里会调用网络接口发送数据包
	// 例如：通过 raw socket、TAP/TUN 接口或网络驱动程序

	// 模拟网络发送延迟
	time.Sleep(time.Microsecond * time.Duration(packet.Size/100))

	// 模拟网络发送成功率（99.9%）
	if time.Now().UnixNano()%1000 == 0 {
		return fmt.Errorf("network send failed: simulated network error")
	}

	return nil
}

// AddClassificationRule 添加流量分类规则
//
// 参数：
//   - rule: 分类规则
//
// 返回值：
//   - error: 添加成功返回nil，失败返回错误信息
func (qos *Engine) AddClassificationRule(rule ClassificationRule) error {
	qos.classifier.mu.Lock()
	defer qos.classifier.mu.Unlock()

	rule.CreatedAt = time.Now()
	qos.classifier.rules = append(qos.classifier.rules, rule)

	// 按优先级排序
	sort.Slice(qos.classifier.rules, func(i, j int) bool {
		return qos.classifier.rules[i].Priority < qos.classifier.rules[j].Priority
	})

	return nil
}

// RemoveClassificationRule 删除流量分类规则
//
// 参数：
//   - ruleID: 规则ID
//
// 返回值：
//   - error: 删除成功返回nil，失败返回错误信息
func (qos *Engine) RemoveClassificationRule(ruleID string) error {
	qos.classifier.mu.Lock()
	defer qos.classifier.mu.Unlock()

	for i, rule := range qos.classifier.rules {
		if rule.ID == ruleID {
			qos.classifier.rules = append(qos.classifier.rules[:i], qos.classifier.rules[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("规则不存在: %s", ruleID)
}

// CreateQueue 创建流量队列
//
// 参数：
//   - queue: 队列配置
//
// 返回值：
//   - error: 创建成功返回nil，失败返回错误信息
func (qos *Engine) CreateQueue(queue *TrafficQueue) error {
	qos.queueManager.mu.Lock()
	defer qos.queueManager.mu.Unlock()

	if len(qos.queueManager.queues) >= qos.queueManager.maxQueues {
		return fmt.Errorf("队列数量已达上限")
	}

	if _, exists := qos.queueManager.queues[queue.ID]; exists {
		return fmt.Errorf("队列已存在: %s", queue.ID)
	}

	// 初始化队列
	queue.packets = make([]*QueuedPacket, 0, queue.MaxPackets)
	queue.currentBytes = 0
	queue.CreatedAt = time.Now()
	queue.stats = QueueStats{}

	// 创建流量整形器（如果需要）
	if queue.MaxBandwidth > 0 {
		queue.shaper = NewTrafficShaper("token_bucket", queue.MaxBandwidth, queue.MaxBandwidth/8)
	}

	// 创建带宽限制器（如果需要）
	if queue.MaxBandwidth > 0 {
		queue.limiter = NewBandwidthLimiter(queue.MaxBandwidth, 1*time.Second)
	}

	qos.queueManager.queues[queue.ID] = queue

	return nil
}

// DeleteQueue 删除流量队列
//
// 参数：
//   - queueID: 队列ID
//
// 返回值：
//   - error: 删除成功返回nil，失败返回错误信息
func (qos *Engine) DeleteQueue(queueID string) error {
	qos.queueManager.mu.Lock()
	defer qos.queueManager.mu.Unlock()

	if _, exists := qos.queueManager.queues[queueID]; !exists {
		return fmt.Errorf("队列不存在: %s", queueID)
	}

	delete(qos.queueManager.queues, queueID)

	return nil
}

// GetQueues 获取所有队列
//
// 返回值：
//   - map[string]*TrafficQueue: 队列映射
func (qos *Engine) GetQueues() map[string]*TrafficQueue {
	qos.queueManager.mu.RLock()
	defer qos.queueManager.mu.RUnlock()

	queues := make(map[string]*TrafficQueue)
	for id, queue := range qos.queueManager.queues {
		queues[id] = queue
	}

	return queues
}

// GetStats 获取QoS统计信息
//
// 返回值：
//   - Stats: 统计信息
func (qos *Engine) GetStats() Stats {
	qos.mu.RLock()
	defer qos.mu.RUnlock()

	return qos.stats
}

// IsRunning 检查QoS引擎是否运行
//
// 返回值：
//   - bool: 运行状态
func (qos *Engine) IsRunning() bool {
	qos.mu.RLock()
	defer qos.mu.RUnlock()

	return qos.running
}

// SetConfig 设置QoS配置
//
// 参数：
//   - config: QoS配置
func (qos *Engine) SetConfig(config Config) {
	qos.mu.Lock()
	defer qos.mu.Unlock()

	qos.config = config
}

// GetConfig 获取QoS配置
//
// 返回值：
//   - Config: QoS配置
func (qos *Engine) GetConfig() Config {
	qos.mu.RLock()
	defer qos.mu.RUnlock()

	return qos.config
}

// 内部辅助方法

// statsWorker 统计工作协程
func (qos *Engine) statsWorker() {
	ticker := time.NewTicker(qos.config.StatsInterval)
	defer ticker.Stop()

	for qos.IsRunning() {
		<-ticker.C
		qos.updateStats()
	}
}

// cleanupWorker 清理工作协程
func (qos *Engine) cleanupWorker() {
	ticker := time.NewTicker(qos.config.CleanupInterval)
	defer ticker.Stop()

	for qos.IsRunning() {
		<-ticker.C
		qos.cleanup()
	}
}

// updateStats 更新统计信息
func (qos *Engine) updateStats() {
	// 更新队列统计
	qos.queueManager.mu.RLock()
	for queueID, queue := range qos.queueManager.queues {
		qos.mu.Lock()
		qos.stats.QueueStats[queueID] = queue.stats
		qos.mu.Unlock()
	}
	qos.queueManager.mu.RUnlock()
}

// cleanup 清理过期数据
func (qos *Engine) cleanup() {
	// 清理过期的带宽采样数据
	for _, limiter := range qos.limiters {
		limiter.cleanup()
	}
}

// 调度器实现

// Schedule 优先级调度
func (ps *PriorityScheduler) Schedule(queues map[string]*TrafficQueue) string {
	var selectedQueue string
	highestPriority := int(^uint(0) >> 1) // 最大int值

	for queueID, queue := range queues {
		if len(queue.packets) > 0 && queue.Priority < highestPriority {
			highestPriority = queue.Priority
			selectedQueue = queueID
		}
	}

	return selectedQueue
}

// UpdateWeights 更新权重
func (ps *PriorityScheduler) UpdateWeights(weights map[string]int) {
	ps.weights = weights
}

// Schedule 加权公平调度
func (wfs *WeightedFairScheduler) Schedule(queues map[string]*TrafficQueue) string {
	var selectedQueue string
	minVirtualTime := uint64(^uint64(0)) // 最大uint64值

	for queueID, queue := range queues {
		if len(queue.packets) > 0 {
			vt, exists := wfs.virtualTime[queueID]
			if !exists {
				vt = 0
				wfs.virtualTime[queueID] = vt
			}

			if vt < minVirtualTime {
				minVirtualTime = vt
				selectedQueue = queueID
			}
		}
	}

	// 更新虚拟时间
	if selectedQueue != "" {
		weight, exists := wfs.weights[selectedQueue]
		if !exists {
			weight = 1
		}
		wfs.virtualTime[selectedQueue] += uint64(1000 / weight) // 简化的虚拟时间计算
	}

	return selectedQueue
}

// UpdateWeights 更新权重
func (wfs *WeightedFairScheduler) UpdateWeights(weights map[string]int) {
	wfs.weights = weights
}

// 流量整形器实现

// NewTrafficShaper 创建流量整形器
func NewTrafficShaper(algorithm string, rate, burstSize uint64) *TrafficShaper {
	return &TrafficShaper{
		algorithm:  algorithm,
		rate:       rate,
		burstSize:  burstSize,
		tokens:     burstSize,
		lastUpdate: time.Now(),
		stats:      ShaperStats{},
	}
}

// AllowPacket 检查是否允许数据包通过
func (ts *TrafficShaper) AllowPacket(size int) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(ts.lastUpdate)
	ts.lastUpdate = now

	// 根据算法处理
	switch ts.algorithm {
	case "token_bucket":
		return ts.tokenBucketAllow(size, elapsed)
	case "leaky_bucket":
		return ts.leakyBucketAllow(size, elapsed)
	default:
		return true
	}
}

// tokenBucketAllow 令牌桶算法
func (ts *TrafficShaper) tokenBucketAllow(size int, elapsed time.Duration) bool {
	// 添加令牌
	tokensToAdd := uint64(elapsed.Seconds() * float64(ts.rate))
	ts.tokens += tokensToAdd
	if ts.tokens > ts.burstSize {
		ts.tokens = ts.burstSize
	}

	ts.stats.TokensGenerated += tokensToAdd

	// 检查是否有足够的令牌
	if ts.tokens >= uint64(size) {
		ts.tokens -= uint64(size)
		ts.stats.TokensConsumed += uint64(size)
		ts.stats.PacketsShaped++
		ts.stats.BytesShaped += uint64(size)
		return true
	}

	ts.stats.PacketsDropped++
	return false
}

// leakyBucketAllow 漏桶算法
func (ts *TrafficShaper) leakyBucketAllow(size int, elapsed time.Duration) bool {
	// 简化的漏桶实现
	// 实际实现需要维护一个队列
	return ts.tokenBucketAllow(size, elapsed)
}

// 带宽限制器实现

// NewBandwidthLimiter 创建带宽限制器
func NewBandwidthLimiter(maxBandwidth uint64, window time.Duration) *BandwidthLimiter {
	return &BandwidthLimiter{
		maxBandwidth: maxBandwidth,
		window:       window,
		samples:      make([]BandwidthSample, 0),
		stats:        LimiterStats{},
	}
}

// AllowPacket 检查是否允许数据包通过
func (bl *BandwidthLimiter) AllowPacket(size int) bool {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	now := time.Now()

	// 添加新采样
	bl.samples = append(bl.samples, BandwidthSample{
		Timestamp: now,
		Bytes:     uint64(size),
	})

	// 清理过期采样
	bl.cleanupSamples(now)

	// 计算当前带宽使用
	bl.calculateCurrentUsage()

	// 检查是否超过限制
	if bl.currentUsage+uint64(size) > bl.maxBandwidth {
		bl.stats.PacketsDropped++
		return false
	}

	bl.stats.PacketsLimited++
	bl.stats.BytesLimited += uint64(size)
	bl.stats.CurrentBandwidth = bl.currentUsage

	if bl.currentUsage > bl.stats.PeakBandwidth {
		bl.stats.PeakBandwidth = bl.currentUsage
	}

	return true
}

// cleanupSamples 清理过期采样
func (bl *BandwidthLimiter) cleanupSamples(now time.Time) {
	cutoff := now.Add(-bl.window)

	i := 0
	for i < len(bl.samples) && bl.samples[i].Timestamp.Before(cutoff) {
		i++
	}

	if i > 0 {
		bl.samples = bl.samples[i:]
	}
}

// calculateCurrentUsage 计算当前带宽使用
func (bl *BandwidthLimiter) calculateCurrentUsage() {
	var totalBytes uint64
	for _, sample := range bl.samples {
		totalBytes += sample.Bytes
	}

	bl.currentUsage = totalBytes * 8 / uint64(bl.window.Seconds()) // 转换为bps
}

// cleanup 清理过期数据
func (bl *BandwidthLimiter) cleanup() {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	bl.cleanupSamples(time.Now())
}

// 动态调整和拥塞控制相关结构体和方法

// CongestionController 拥塞控制器
type CongestionController struct {
	mu sync.RWMutex

	// 拥塞检测参数
	congestionThreshold float64       // 拥塞阈值（队列利用率）
	congestionWindow    time.Duration // 拥塞检测窗口

	// 拥塞状态
	congestionLevel     float64 // 当前拥塞级别 (0.0-1.0)
	lastCongestionCheck time.Time

	// 动态调整参数
	adaptiveEnabled  bool
	adjustmentFactor float64 // 调整因子
	minBandwidth     uint64  // 最小带宽保证
	maxBandwidth     uint64  //nolint:unused // 最大带宽限制，为拥塞控制保留

	// 统计信息
	congestionEvents uint64
	adjustmentEvents uint64
}

// FairnessController 公平性控制器
type FairnessController struct {
	mu sync.RWMutex

	// 公平性算法类型
	algorithm string // "weighted_fair", "deficit_round_robin", "stochastic_fair"

	// 权重管理
	classWeights   map[string]int     // 类别权重
	dynamicWeights map[string]float64 // 动态权重

	// 公平性统计
	classUsage    map[string]uint64 // 各类别使用量
	fairnessIndex float64           // 公平性指数

	// 调整参数
	adjustmentInterval time.Duration
	lastAdjustment     time.Time
}

// AdaptiveQoS 自适应QoS管理器
type AdaptiveQoS struct {
	mu sync.RWMutex

	// 关联的QoS引擎
	qosEngine *Engine

	// 控制器
	congestionController *CongestionController
	fairnessController   *FairnessController

	// 自适应参数
	enabled            bool
	learningRate       float64
	adaptationInterval time.Duration

	// 历史数据
	performanceHistory []PerformanceMetrics
	maxHistorySize     int

	// 预测模型
	trafficPredictor *TrafficPredictor
}

// PerformanceMetrics 性能指标
type PerformanceMetrics struct {
	Timestamp        time.Time
	Throughput       uint64
	Latency          time.Duration
	PacketLoss       float64
	QueueUtilization float64
	CongestionLevel  float64
	FairnessIndex    float64
}

// TrafficPredictor 流量预测器
type TrafficPredictor struct {
	mu sync.RWMutex

	// 预测模型参数
	windowSize        int
	predictionHorizon time.Duration

	// 历史数据
	trafficHistory []TrafficSample

	// 预测结果
	predictedLoad  float64
	confidence     float64
	lastPrediction time.Time
}

// TrafficSample 流量样本
type TrafficSample struct {
	Timestamp  time.Time
	Bandwidth  uint64
	PacketRate uint64
	QueueDepth int
}

// NewCongestionController 创建拥塞控制器
func NewCongestionController() *CongestionController {
	return &CongestionController{
		congestionThreshold: 0.8, // 80%队列利用率触发拥塞控制
		congestionWindow:    5 * time.Second,
		adaptiveEnabled:     true,
		adjustmentFactor:    0.1, // 10%调整步长
		lastCongestionCheck: time.Now(),
	}
}

// NewFairnessController 创建公平性控制器
func NewFairnessController() *FairnessController {
	return &FairnessController{
		algorithm:          "weighted_fair",
		classWeights:       make(map[string]int),
		dynamicWeights:     make(map[string]float64),
		classUsage:         make(map[string]uint64),
		adjustmentInterval: 10 * time.Second,
		lastAdjustment:     time.Now(),
	}
}

// NewAdaptiveQoS 创建自适应QoS管理器
func NewAdaptiveQoS(qosEngine *Engine) *AdaptiveQoS {
	return &AdaptiveQoS{
		qosEngine:            qosEngine,
		congestionController: NewCongestionController(),
		fairnessController:   NewFairnessController(),
		enabled:              true,
		learningRate:         0.01,
		adaptationInterval:   30 * time.Second,
		maxHistorySize:       1000,
		trafficPredictor:     NewTrafficPredictor(),
	}
}

// NewTrafficPredictor 创建流量预测器
func NewTrafficPredictor() *TrafficPredictor {
	return &TrafficPredictor{
		windowSize:        100,
		predictionHorizon: 60 * time.Second,
		trafficHistory:    make([]TrafficSample, 0),
	}
}

// Start 启动自适应QoS
func (aq *AdaptiveQoS) Start() {
	aq.mu.Lock()
	defer aq.mu.Unlock()

	if !aq.enabled {
		return
	}

	// 启动拥塞控制
	go aq.congestionControlLoop()

	// 启动公平性控制
	go aq.fairnessControlLoop()

	// 启动自适应调整
	go aq.adaptiveControlLoop()

	// 启动流量预测
	go aq.trafficPredictionLoop()
}

// congestionControlLoop 拥塞控制循环
func (aq *AdaptiveQoS) congestionControlLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !aq.enabled {
			return
		}
		aq.detectAndControlCongestion()
	}
}

// detectAndControlCongestion 检测和控制拥塞
func (aq *AdaptiveQoS) detectAndControlCongestion() {
	cc := aq.congestionController
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// 计算当前拥塞级别
	congestionLevel := aq.calculateCongestionLevel()
	cc.congestionLevel = congestionLevel

	// 检测是否发生拥塞
	if congestionLevel > cc.congestionThreshold {
		cc.congestionEvents++

		if cc.adaptiveEnabled {
			// 执行拥塞控制措施
			aq.applyCongestionControl(congestionLevel)
		}
	}

	cc.lastCongestionCheck = time.Now()
}

// calculateCongestionLevel 计算拥塞级别
func (aq *AdaptiveQoS) calculateCongestionLevel() float64 {
	queues := aq.qosEngine.GetQueues()
	if len(queues) == 0 {
		return 0.0
	}

	totalUtilization := 0.0
	queueCount := 0

	for _, queue := range queues {
		if queue.MaxPackets > 0 {
			utilization := float64(len(queue.packets)) / float64(queue.MaxPackets)
			totalUtilization += utilization
			queueCount++
		}
	}

	if queueCount == 0 {
		return 0.0
	}

	return totalUtilization / float64(queueCount)
}

// applyCongestionControl 应用拥塞控制
func (aq *AdaptiveQoS) applyCongestionControl(congestionLevel float64) {
	cc := aq.congestionController

	// 计算调整幅度
	adjustmentRatio := 1.0 - (congestionLevel-cc.congestionThreshold)*cc.adjustmentFactor
	if adjustmentRatio < 0.5 {
		adjustmentRatio = 0.5 // 最多减少50%
	}

	// 动态调整队列参数
	queues := aq.qosEngine.GetQueues()
	for _, queue := range queues {
		// 调整带宽限制
		if queue.limiter != nil {
			newBandwidth := uint64(float64(queue.MaxBandwidth) * adjustmentRatio)
			if newBandwidth < cc.minBandwidth {
				newBandwidth = cc.minBandwidth
			}
			queue.limiter.maxBandwidth = newBandwidth
		}

		// 调整队列大小
		newMaxPackets := int(float64(queue.MaxPackets) * adjustmentRatio)
		if newMaxPackets < 10 {
			newMaxPackets = 10 // 最小队列大小
		}
		queue.MaxPackets = newMaxPackets
	}

	cc.adjustmentEvents++
}

// fairnessControlLoop 公平性控制循环
func (aq *AdaptiveQoS) fairnessControlLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !aq.enabled {
			return
		}
		aq.adjustFairness()
	}
}

// adjustFairness 调整公平性
func (aq *AdaptiveQoS) adjustFairness() {
	fc := aq.fairnessController
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// 收集各类别的使用统计
	aq.collectClassUsageStats()

	// 计算公平性指数
	fc.fairnessIndex = aq.calculateFairnessIndex()

	// 根据公平性算法调整权重
	switch fc.algorithm {
	case "weighted_fair":
		aq.adjustWeightedFairWeights()
	case "deficit_round_robin":
		aq.adjustDeficitRoundRobinWeights()
	case "stochastic_fair":
		aq.adjustStochasticFairWeights()
	}

	fc.lastAdjustment = time.Now()
}

// collectClassUsageStats 收集类别使用统计
func (aq *AdaptiveQoS) collectClassUsageStats() {
	fc := aq.fairnessController
	stats := aq.qosEngine.GetStats()

	for class, classStats := range stats.ClassStats {
		fc.classUsage[class] = classStats.BytesClassified
	}
}

// calculateFairnessIndex 计算公平性指数（Jain's Fairness Index）
func (aq *AdaptiveQoS) calculateFairnessIndex() float64 {
	fc := aq.fairnessController

	if len(fc.classUsage) < 2 {
		return 1.0 // 只有一个或没有类别时认为是公平的
	}

	var sum, sumSquares float64
	count := 0

	for _, usage := range fc.classUsage {
		if usage > 0 {
			sum += float64(usage)
			sumSquares += float64(usage) * float64(usage)
			count++
		}
	}

	if count == 0 || sumSquares == 0 {
		return 1.0
	}

	// Jain's Fairness Index: (sum)^2 / (n * sumSquares)
	return (sum * sum) / (float64(count) * sumSquares)
}

// adjustWeightedFairWeights 调整加权公平权重
func (aq *AdaptiveQoS) adjustWeightedFairWeights() {
	fc := aq.fairnessController

	// 计算各类别的理想权重
	totalUsage := uint64(0)
	for _, usage := range fc.classUsage {
		totalUsage += usage
	}

	if totalUsage == 0 {
		return
	}

	// 根据使用量反向调整权重（使用量高的类别降低权重）
	for class, usage := range fc.classUsage {
		currentWeight, exists := fc.classWeights[class]
		if !exists {
			currentWeight = 100 // 默认权重
		}

		usageRatio := float64(usage) / float64(totalUsage)
		targetWeight := 1.0 / (usageRatio + 0.1) // 避免除零

		// 平滑调整
		newWeight := float64(currentWeight)*0.9 + targetWeight*0.1
		fc.dynamicWeights[class] = newWeight
	}

	// 更新调度器权重
	weights := make(map[string]int)
	for class, weight := range fc.dynamicWeights {
		weights[class] = int(weight)
	}
	aq.qosEngine.queueManager.scheduler.UpdateWeights(weights)
}

// adjustDeficitRoundRobinWeights 调整赤字轮询权重
func (aq *AdaptiveQoS) adjustDeficitRoundRobinWeights() {
	// DRR算法的权重调整实现
	// 这里是简化实现，实际应该根据赤字计数器进行调整
	aq.adjustWeightedFairWeights()
}

// adjustStochasticFairWeights 调整随机公平权重
func (aq *AdaptiveQoS) adjustStochasticFairWeights() {
	// SFQ算法的权重调整实现
	// 这里是简化实现，实际应该根据哈希桶进行调整
	aq.adjustWeightedFairWeights()
}

// adaptiveControlLoop 自适应控制循环
func (aq *AdaptiveQoS) adaptiveControlLoop() {
	ticker := time.NewTicker(aq.adaptationInterval)
	defer ticker.Stop()

	for range ticker.C {
		if !aq.enabled {
			return
		}
		aq.performAdaptiveAdjustment()
	}
}

// performAdaptiveAdjustment 执行自适应调整
func (aq *AdaptiveQoS) performAdaptiveAdjustment() {
	aq.mu.Lock()
	defer aq.mu.Unlock()

	// 收集当前性能指标
	metrics := aq.collectPerformanceMetrics()

	// 添加到历史记录
	aq.addPerformanceHistory(metrics)

	// 基于历史数据进行学习和调整
	aq.learnAndAdjust()
}

// collectPerformanceMetrics 收集性能指标
func (aq *AdaptiveQoS) collectPerformanceMetrics() PerformanceMetrics {
	stats := aq.qosEngine.GetStats()

	// 计算吞吐量
	throughput := stats.BytesProcessed

	// 计算平均延迟
	latency := stats.AverageLatency

	// 计算丢包率
	packetLoss := 0.0
	if stats.PacketsProcessed > 0 {
		packetLoss = float64(stats.PacketsDropped) / float64(stats.PacketsProcessed)
	}

	// 计算队列利用率
	queueUtilization := aq.calculateCongestionLevel()

	return PerformanceMetrics{
		Timestamp:        time.Now(),
		Throughput:       throughput,
		Latency:          latency,
		PacketLoss:       packetLoss,
		QueueUtilization: queueUtilization,
		CongestionLevel:  aq.congestionController.congestionLevel,
		FairnessIndex:    aq.fairnessController.fairnessIndex,
	}
}

// addPerformanceHistory 添加性能历史记录
func (aq *AdaptiveQoS) addPerformanceHistory(metrics PerformanceMetrics) {
	aq.performanceHistory = append(aq.performanceHistory, metrics)

	// 限制历史记录大小
	if len(aq.performanceHistory) > aq.maxHistorySize {
		aq.performanceHistory = aq.performanceHistory[1:]
	}
}

// learnAndAdjust 学习和调整
func (aq *AdaptiveQoS) learnAndAdjust() {
	if len(aq.performanceHistory) < 10 {
		return // 需要足够的历史数据
	}

	// 分析性能趋势
	recentMetrics := aq.performanceHistory[len(aq.performanceHistory)-10:]

	// 计算性能变化趋势
	latencyTrend := aq.calculateTrend(recentMetrics, "latency")
	throughputTrend := aq.calculateTrend(recentMetrics, "throughput")
	packetLossTrend := aq.calculateTrend(recentMetrics, "packet_loss")

	// 根据趋势调整参数
	if latencyTrend > 0.1 { // 延迟增加趋势
		aq.adjustForHighLatency()
	}

	if throughputTrend < -0.1 { // 吞吐量下降趋势
		aq.adjustForLowThroughput()
	}

	if packetLossTrend > 0.05 { // 丢包率增加趋势
		aq.adjustForHighPacketLoss()
	}
}

// calculateTrend 计算趋势
func (aq *AdaptiveQoS) calculateTrend(metrics []PerformanceMetrics, metricType string) float64 {
	if len(metrics) < 2 {
		return 0.0
	}

	var values []float64
	for _, m := range metrics {
		switch metricType {
		case "latency":
			values = append(values, float64(m.Latency.Nanoseconds()))
		case "throughput":
			values = append(values, float64(m.Throughput))
		case "packet_loss":
			values = append(values, m.PacketLoss)
		}
	}

	// 简单线性回归计算趋势
	n := float64(len(values))
	sumX, sumY, sumXY, sumX2 := 0.0, 0.0, 0.0, 0.0

	for i, y := range values {
		x := float64(i)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	// 计算斜率（趋势）
	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)
	return slope
}

// adjustForHighLatency 针对高延迟进行调整
func (aq *AdaptiveQoS) adjustForHighLatency() {
	// 增加高优先级队列的权重
	// 减少低优先级队列的大小
	// 调整调度算法参数
}

// adjustForLowThroughput 针对低吞吐量进行调整
func (aq *AdaptiveQoS) adjustForLowThroughput() {
	// 增加带宽分配
	// 调整流量整形参数
	// 优化队列调度
}

// adjustForHighPacketLoss 针对高丢包率进行调整
func (aq *AdaptiveQoS) adjustForHighPacketLoss() {
	// 增加队列大小
	// 调整拥塞控制参数
	// 启用更积极的流量控制
}

// trafficPredictionLoop 流量预测循环
func (aq *AdaptiveQoS) trafficPredictionLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !aq.enabled {
			return
		}
		aq.updateTrafficPrediction()
	}
}

// updateTrafficPrediction 更新流量预测
func (aq *AdaptiveQoS) updateTrafficPrediction() {
	tp := aq.trafficPredictor
	tp.mu.Lock()
	defer tp.mu.Unlock()

	// 收集当前流量样本
	sample := aq.collectTrafficSample()
	tp.trafficHistory = append(tp.trafficHistory, sample)

	// 限制历史记录大小
	if len(tp.trafficHistory) > tp.windowSize {
		tp.trafficHistory = tp.trafficHistory[1:]
	}

	// 执行预测
	if len(tp.trafficHistory) >= 10 {
		tp.predictedLoad, tp.confidence = aq.predictTrafficLoad()
		tp.lastPrediction = time.Now()
	}
}

// collectTrafficSample 收集流量样本
func (aq *AdaptiveQoS) collectTrafficSample() TrafficSample {
	stats := aq.qosEngine.GetStats()

	// 计算当前队列深度
	queues := aq.qosEngine.GetQueues()
	totalQueueDepth := 0
	for _, queue := range queues {
		totalQueueDepth += len(queue.packets)
	}

	return TrafficSample{
		Timestamp:  time.Now(),
		Bandwidth:  stats.BytesProcessed,
		PacketRate: stats.PacketsProcessed,
		QueueDepth: totalQueueDepth,
	}
}

// predictTrafficLoad 预测流量负载
func (aq *AdaptiveQoS) predictTrafficLoad() (float64, float64) {
	tp := aq.trafficPredictor

	if len(tp.trafficHistory) < 10 {
		return 0.0, 0.0
	}

	// 简单的移动平均预测
	recentSamples := tp.trafficHistory[len(tp.trafficHistory)-10:]

	var totalBandwidth uint64
	for _, sample := range recentSamples {
		totalBandwidth += sample.Bandwidth
	}

	avgBandwidth := float64(totalBandwidth) / float64(len(recentSamples))

	// 计算预测置信度（基于方差）
	var variance float64
	for _, sample := range recentSamples {
		diff := float64(sample.Bandwidth) - avgBandwidth
		variance += diff * diff
	}
	variance /= float64(len(recentSamples))

	// 置信度与方差成反比
	confidence := 1.0 / (1.0 + variance/avgBandwidth)

	return avgBandwidth, confidence
}

// GetAdaptiveStats 获取自适应QoS统计信息
func (aq *AdaptiveQoS) GetAdaptiveStats() map[string]interface{} {
	aq.mu.RLock()
	defer aq.mu.RUnlock()

	stats := make(map[string]interface{})

	// 拥塞控制统计
	stats["congestion_level"] = aq.congestionController.congestionLevel
	stats["congestion_events"] = aq.congestionController.congestionEvents
	stats["adjustment_events"] = aq.congestionController.adjustmentEvents

	// 公平性统计
	stats["fairness_index"] = aq.fairnessController.fairnessIndex
	stats["class_weights"] = aq.fairnessController.dynamicWeights

	// 预测统计
	stats["predicted_load"] = aq.trafficPredictor.predictedLoad
	stats["prediction_confidence"] = aq.trafficPredictor.confidence

	// 性能历史
	if len(aq.performanceHistory) > 0 {
		latest := aq.performanceHistory[len(aq.performanceHistory)-1]
		stats["latest_metrics"] = latest
	}

	return stats
}
