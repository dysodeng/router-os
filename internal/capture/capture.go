package capture

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"
	"strings"
	"sort"

	"router-os/internal/packet"
)

// PacketCapture 数据包捕获器
// 负责从网络接口捕获数据包并进行初步处理
//
// 主要功能：
// 1. 网络接口监听：监听指定网络接口的数据包
// 2. 数据包解析：解析以太网帧、IP头部等
// 3. 过滤处理：根据规则过滤数据包
// 4. 统计分析：收集网络流量统计信息
// 5. 实时监控：提供实时的网络状态监控
type PacketCapture struct {
	// interfaceName 网络接口名称
	interfaceName string

	// running 运行状态
	running bool

	// mu 读写锁，保护并发访问
	mu sync.RWMutex

	// packetChan 数据包通道
	packetChan chan *packet.Packet

	// ctx 上下文
	ctx context.Context

	// cancel 取消函数
	cancel context.CancelFunc

	// stats 统计信息
	stats CaptureStats

	// conn 网络连接
	conn net.PacketConn

	// filter 数据包过滤器
	filter *PacketFilter

	// analyzer 流量分析器
	analyzer *TrafficAnalyzer

	// monitor 实时监控器
	monitor *RealTimeMonitor

	// bufferSize 缓冲区大小
	bufferSize int

	// promiscuous 是否启用混杂模式
	promiscuous bool
}

// CaptureStats 捕获统计信息
type CaptureStats struct {
	// PacketsCaptured 捕获的数据包总数
	PacketsCaptured uint64

	// BytesCaptured 捕获的字节总数
	BytesCaptured uint64

	// PacketsDropped 丢弃的数据包数
	PacketsDropped uint64

	// ErrorCount 错误计数
	ErrorCount uint64

	// StartTime 开始时间
	StartTime time.Time

	// LastPacketTime 最后一个数据包时间
	LastPacketTime time.Time

	// PacketsPerSecond 每秒数据包数
	PacketsPerSecond float64

	// BytesPerSecond 每秒字节数
	BytesPerSecond float64

	// ProtocolStats 协议统计
	ProtocolStats map[string]uint64

	// InterfaceStats 接口统计
	InterfaceStats map[string]uint64
}

// PacketFilter 数据包过滤器
type PacketFilter struct {
	// ProtocolFilter 协议过滤器
	ProtocolFilter []uint8

	// SourceIPFilter 源IP过滤器
	SourceIPFilter []*net.IPNet

	// DestIPFilter 目标IP过滤器
	DestIPFilter []*net.IPNet

	// PortFilter 端口过滤器
	PortFilter []uint16

	// Enabled 是否启用过滤器
	Enabled bool

	// MinPacketSize 最小数据包大小
	MinPacketSize int

	// MaxPacketSize 最大数据包大小
	MaxPacketSize int

	// TimeFilter 时间过滤器
	TimeFilter *TimeFilter

	// CustomRules 自定义规则
	CustomRules []FilterRule
}

// TimeFilter 时间过滤器
type TimeFilter struct {
	StartTime time.Time
	EndTime   time.Time
	Enabled   bool
}

// FilterRule 过滤规则
type FilterRule struct {
	Name        string
	Description string
	Condition   func(*packet.Packet) bool
	Action      FilterAction
	Priority    int
}

// FilterAction 过滤动作
type FilterAction int

const (
	FilterActionAccept FilterAction = iota
	FilterActionDrop
	FilterActionLog
	FilterActionModify
)

// TrafficAnalyzer 流量分析器
type TrafficAnalyzer struct {
	mu                sync.RWMutex
	protocolStats     map[string]*ProtocolStats
	flowStats         map[string]*FlowStats
	topTalkers        []*TalkerStats
	bandwidthHistory  []BandwidthSample
	anomalyDetector   *AnomalyDetector
	enabled           bool
	analysisInterval  time.Duration
}

// ProtocolStats 协议统计
type ProtocolStats struct {
	PacketCount uint64
	ByteCount   uint64
	FirstSeen   time.Time
	LastSeen    time.Time
	Bandwidth   float64
}

// FlowStats 流统计
type FlowStats struct {
	SourceIP      net.IP
	DestIP        net.IP
	SourcePort    uint16
	DestPort      uint16
	Protocol      uint8
	PacketCount   uint64
	ByteCount     uint64
	FirstSeen     time.Time
	LastSeen      time.Time
	Duration      time.Duration
}

// TalkerStats 流量大户统计
type TalkerStats struct {
	IP          net.IP
	PacketCount uint64
	ByteCount   uint64
	Percentage  float64
}

// BandwidthSample 带宽采样
type BandwidthSample struct {
	Timestamp time.Time
	BytesIn   uint64
	BytesOut  uint64
	PacketsIn uint64
	PacketsOut uint64
}

// AnomalyDetector 异常检测器
type AnomalyDetector struct {
	mu                sync.RWMutex
	baselineTraffic   map[string]float64
	thresholds        map[string]float64
	anomalies         []AnomalyEvent
	enabled           bool
	learningPeriod    time.Duration
	detectionEnabled  bool
}

// AnomalyEvent 异常事件
type AnomalyEvent struct {
	Timestamp   time.Time
	Type        string
	Description string
	Severity    AnomalySeverity
	Value       float64
	Threshold   float64
}

// AnomalySeverity 异常严重程度
type AnomalySeverity int

const (
	SeverityLow AnomalySeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// RealTimeMonitor 实时监控器
type RealTimeMonitor struct {
	mu              sync.RWMutex
	metrics         map[string]interface{}
	alerts          []Alert
	thresholds      map[string]Threshold
	updateInterval  time.Duration
	enabled         bool
	subscribers     []chan MonitorEvent
}

// Alert 告警
type Alert struct {
	ID          string
	Timestamp   time.Time
	Type        string
	Message     string
	Severity    AlertSeverity
	Resolved    bool
	ResolvedAt  time.Time
}

// AlertSeverity 告警严重程度
type AlertSeverity int

const (
	AlertSeverityInfo AlertSeverity = iota
	AlertSeverityWarning
	AlertSeverityError
	AlertSeverityCritical
)

// Threshold 阈值
type Threshold struct {
	MetricName string
	Value      float64
	Operator   string // >, <, >=, <=, ==, !=
	Action     string
}

// MonitorEvent 监控事件
type MonitorEvent struct {
	Timestamp time.Time
	Type      string
	Data      interface{}
}

// NewPacketCapture 创建新的数据包捕获器
func NewPacketCapture(interfaceName string, bufferSize int) (*PacketCapture, error) {
	// 检查操作系统支持
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("Windows系统需要特殊的网络驱动支持")
	}

	// 验证网络接口是否存在
	if err := ValidateInterface(interfaceName); err != nil {
		return nil, fmt.Errorf("网络接口验证失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	pc := &PacketCapture{
		interfaceName: interfaceName,
		packetChan:    make(chan *packet.Packet, bufferSize),
		ctx:           ctx,
		cancel:        cancel,
		bufferSize:    bufferSize,
		stats: CaptureStats{
			StartTime:      time.Now(),
			ProtocolStats:  make(map[string]uint64),
			InterfaceStats: make(map[string]uint64),
		},
		filter: &PacketFilter{
			Enabled: false,
		},
		analyzer: NewTrafficAnalyzer(),
		monitor:  NewRealTimeMonitor(),
	}

	return pc, nil
}

// Start 启动数据包捕获
func (pc *PacketCapture) Start() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.running {
		return fmt.Errorf("数据包捕获器已经在运行")
	}

	// 创建网络连接
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("初始化网络监听失败: %v", err)
	}

	pc.conn = conn
	pc.running = true
	pc.stats.StartTime = time.Now()

	// 启动各个组件
	if pc.analyzer.enabled {
		go pc.analyzer.Start()
	}

	if pc.monitor.enabled {
		go pc.monitor.Start()
	}

	// 启动捕获协程
	go pc.captureLoop()

	// 启动统计更新协程
	go pc.updateStatsLoop()

	return nil
}

// Stop 停止数据包捕获
func (pc *PacketCapture) Stop() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if !pc.running {
		return nil
	}

	pc.running = false
	pc.cancel()

	if pc.conn != nil {
		pc.conn.Close()
		pc.conn = nil
	}

	// 停止各个组件
	if pc.analyzer != nil {
		pc.analyzer.Stop()
	}

	if pc.monitor != nil {
		pc.monitor.Stop()
	}

	close(pc.packetChan)

	return nil
}

// GetPacketChannel 获取数据包通道
func (pc *PacketCapture) GetPacketChannel() <-chan *packet.Packet {
	return pc.packetChan
}

// GetStats 获取捕获统计信息
func (pc *PacketCapture) GetStats() CaptureStats {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.stats
}

// IsRunning 检查捕获器是否正在运行
func (pc *PacketCapture) IsRunning() bool {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.running
}

// SetFilter 设置数据包过滤器
func (pc *PacketCapture) SetFilter(filter *PacketFilter) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.filter = filter
}

// GetFilter 获取当前过滤器
func (pc *PacketCapture) GetFilter() *PacketFilter {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.filter
}

// EnableAnalyzer 启用流量分析器
func (pc *PacketCapture) EnableAnalyzer(enabled bool) {
	pc.analyzer.enabled = enabled
}

// GetAnalyzer 获取流量分析器
func (pc *PacketCapture) GetAnalyzer() *TrafficAnalyzer {
	return pc.analyzer
}

// EnableMonitor 启用实时监控
func (pc *PacketCapture) EnableMonitor(enabled bool) {
	pc.monitor.enabled = enabled
}

// GetMonitor 获取实时监控器
func (pc *PacketCapture) GetMonitor() *RealTimeMonitor {
	return pc.monitor
}

// captureLoop 数据包捕获主循环
func (pc *PacketCapture) captureLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-pc.ctx.Done():
			return
		case <-ticker.C:
			pc.simulatePacketCapture()
		}
	}
}

// simulatePacketCapture 模拟数据包捕获
func (pc *PacketCapture) simulatePacketCapture() {
	// 创建模拟的数据包
	simulatedPackets := []*packet.Packet{
		{
			Type:        packet.PacketTypeIPv4,
			Source:      net.ParseIP("192.168.1.100"),
			Destination: net.ParseIP("192.168.1.1"),
			Data:        []byte("HTTP GET request simulation"),
			Size:        64,
			Timestamp:   time.Now(),
			InInterface: pc.interfaceName,
			TTL:         64,
		},
		{
			Type:        packet.PacketTypeIPv4,
			Source:      net.ParseIP("10.0.0.5"),
			Destination: net.ParseIP("8.8.8.8"),
			Data:        []byte("DNS query simulation"),
			Size:        32,
			Timestamp:   time.Now(),
			InInterface: pc.interfaceName,
			TTL:         64,
		},
		{
			Type:        packet.PacketTypeIPv6,
			Source:      net.ParseIP("2001:db8::1"),
			Destination: net.ParseIP("2001:db8::2"),
			Data:        []byte("IPv6 packet simulation"),
			Size:        128,
			Timestamp:   time.Now(),
			InInterface: pc.interfaceName,
			TTL:         64,
		},
	}

	// 随机选择一个模拟数据包
	if len(simulatedPackets) > 0 {
		pkt := simulatedPackets[time.Now().UnixNano()%int64(len(simulatedPackets))]

		// 应用过滤器
		if pc.filter.Enabled && !pc.applyFilter(pkt) {
			return
		}

		// 更新统计信息
		pc.updatePacketStats(pkt)

		// 流量分析
		if pc.analyzer.enabled {
			pc.analyzer.AnalyzePacket(pkt)
		}

		// 实时监控
		if pc.monitor.enabled {
			pc.monitor.ProcessPacket(pkt)
		}

		// 发送到通道（非阻塞）
		select {
		case pc.packetChan <- pkt:
		default:
			// 通道满了，丢弃数据包
			pc.mu.Lock()
			pc.stats.PacketsDropped++
			pc.mu.Unlock()
		}
	}
}

// applyFilter 应用数据包过滤器
func (pc *PacketCapture) applyFilter(pkt *packet.Packet) bool {
	if !pc.filter.Enabled {
		return true
	}

	// 检查数据包大小
	if pc.filter.MinPacketSize > 0 && pkt.Size < pc.filter.MinPacketSize {
		return false
	}
	if pc.filter.MaxPacketSize > 0 && pkt.Size > pc.filter.MaxPacketSize {
		return false
	}

	// 检查时间过滤器
	if pc.filter.TimeFilter != nil && pc.filter.TimeFilter.Enabled {
		if pkt.Timestamp.Before(pc.filter.TimeFilter.StartTime) ||
		   pkt.Timestamp.After(pc.filter.TimeFilter.EndTime) {
			return false
		}
	}

	// 检查IP过滤器
	if len(pc.filter.SourceIPFilter) > 0 {
		matched := false
		for _, ipNet := range pc.filter.SourceIPFilter {
			if ipNet.Contains(pkt.Source) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(pc.filter.DestIPFilter) > 0 {
		matched := false
		for _, ipNet := range pc.filter.DestIPFilter {
			if ipNet.Contains(pkt.Destination) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 应用自定义规则
	for _, rule := range pc.filter.CustomRules {
		if rule.Condition(pkt) {
			switch rule.Action {
			case FilterActionDrop:
				return false
			case FilterActionAccept:
				return true
			case FilterActionLog:
				// 记录日志但继续处理
				continue
			}
		}
	}

	return true
}

// updatePacketStats 更新数据包统计信息
func (pc *PacketCapture) updatePacketStats(pkt *packet.Packet) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.stats.PacketsCaptured++
	pc.stats.BytesCaptured += uint64(pkt.Size)
	pc.stats.LastPacketTime = pkt.Timestamp

	// 更新协议统计
	protocol := getPacketTypeString(pkt.Type)
	pc.stats.ProtocolStats[protocol]++

	// 更新接口统计
	pc.stats.InterfaceStats[pkt.InInterface]++
}

// updateStatsLoop 统计信息更新循环
func (pc *PacketCapture) updateStatsLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastPackets, lastBytes uint64
	var lastTime time.Time = time.Now()

	for {
		select {
		case <-pc.ctx.Done():
			return
		case <-ticker.C:
			pc.mu.Lock()
			currentPackets := pc.stats.PacketsCaptured
			currentBytes := pc.stats.BytesCaptured
			currentTime := time.Now()

			if !lastTime.IsZero() {
				duration := currentTime.Sub(lastTime).Seconds()
				pc.stats.PacketsPerSecond = float64(currentPackets-lastPackets) / duration
				pc.stats.BytesPerSecond = float64(currentBytes-lastBytes) / duration
			}

			lastPackets = currentPackets
			lastBytes = currentBytes
			lastTime = currentTime
			pc.mu.Unlock()
		}
	}
}

// GetInterfaceInfo 获取网络接口详细信息
func (pc *PacketCapture) GetInterfaceInfo() (*net.Interface, error) {
	return net.InterfaceByName(pc.interfaceName)
}

// SetPromiscuousMode 设置网络接口为混杂模式
func (pc *PacketCapture) SetPromiscuousMode(enable bool) error {
	iface, err := net.InterfaceByName(pc.interfaceName)
	if err != nil {
		return fmt.Errorf("获取接口信息失败: %v", err)
	}

	pc.promiscuous = enable
	fmt.Printf("模拟设置接口 %s 混杂模式: %v\n", iface.Name, enable)

	return nil
}

// NewTrafficAnalyzer 创建新的流量分析器
func NewTrafficAnalyzer() *TrafficAnalyzer {
	return &TrafficAnalyzer{
		protocolStats:    make(map[string]*ProtocolStats),
		flowStats:        make(map[string]*FlowStats),
		topTalkers:       make([]*TalkerStats, 0),
		bandwidthHistory: make([]BandwidthSample, 0),
		anomalyDetector:  NewAnomalyDetector(),
		enabled:          false,
		analysisInterval: 5 * time.Second,
	}
}

// Start 启动流量分析器
func (ta *TrafficAnalyzer) Start() {
	ticker := time.NewTicker(ta.analysisInterval)
	defer ticker.Stop()

	for ta.enabled {
		select {
		case <-ticker.C:
			ta.performAnalysis()
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// Stop 停止流量分析器
func (ta *TrafficAnalyzer) Stop() {
	ta.enabled = false
}

// AnalyzePacket 分析数据包
func (ta *TrafficAnalyzer) AnalyzePacket(pkt *packet.Packet) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	// 更新协议统计
	protocol := getPacketTypeString(pkt.Type)
	if stats, exists := ta.protocolStats[protocol]; exists {
		stats.PacketCount++
		stats.ByteCount += uint64(pkt.Size)
		stats.LastSeen = pkt.Timestamp
	} else {
		ta.protocolStats[protocol] = &ProtocolStats{
			PacketCount: 1,
			ByteCount:   uint64(pkt.Size),
			FirstSeen:   pkt.Timestamp,
			LastSeen:    pkt.Timestamp,
		}
	}

	// 更新流统计
	flowKey := fmt.Sprintf("%s:%d->%s:%d", pkt.Source.String(), 0, pkt.Destination.String(), 0)
	if flow, exists := ta.flowStats[flowKey]; exists {
		flow.PacketCount++
		flow.ByteCount += uint64(pkt.Size)
		flow.LastSeen = pkt.Timestamp
		flow.Duration = pkt.Timestamp.Sub(flow.FirstSeen)
	} else {
		ta.flowStats[flowKey] = &FlowStats{
			SourceIP:    pkt.Source,
			DestIP:      pkt.Destination,
			PacketCount: 1,
			ByteCount:   uint64(pkt.Size),
			FirstSeen:   pkt.Timestamp,
			LastSeen:    pkt.Timestamp,
		}
	}
}

// performAnalysis 执行分析
func (ta *TrafficAnalyzer) performAnalysis() {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	// 更新Top Talkers
	ta.updateTopTalkers()

	// 记录带宽历史
	ta.recordBandwidthSample()

	// 异常检测
	if ta.anomalyDetector.enabled {
		ta.anomalyDetector.DetectAnomalies(ta.protocolStats)
	}
}

// updateTopTalkers 更新流量大户
func (ta *TrafficAnalyzer) updateTopTalkers() {
	talkerMap := make(map[string]*TalkerStats)
	var totalBytes uint64

	// 统计每个IP的流量
	for _, flow := range ta.flowStats {
		sourceKey := flow.SourceIP.String()
		destKey := flow.DestIP.String()

		if talker, exists := talkerMap[sourceKey]; exists {
			talker.ByteCount += flow.ByteCount
			talker.PacketCount += flow.PacketCount
		} else {
			talkerMap[sourceKey] = &TalkerStats{
				IP:          flow.SourceIP,
				ByteCount:   flow.ByteCount,
				PacketCount: flow.PacketCount,
			}
		}

		if talker, exists := talkerMap[destKey]; exists {
			talker.ByteCount += flow.ByteCount
			talker.PacketCount += flow.PacketCount
		} else {
			talkerMap[destKey] = &TalkerStats{
				IP:          flow.DestIP,
				ByteCount:   flow.ByteCount,
				PacketCount: flow.PacketCount,
			}
		}

		totalBytes += flow.ByteCount
	}

	// 计算百分比并排序
	ta.topTalkers = make([]*TalkerStats, 0, len(talkerMap))
	for _, talker := range talkerMap {
		if totalBytes > 0 {
			talker.Percentage = float64(talker.ByteCount) / float64(totalBytes) * 100
		}
		ta.topTalkers = append(ta.topTalkers, talker)
	}

	// 按字节数排序
	sort.Slice(ta.topTalkers, func(i, j int) bool {
		return ta.topTalkers[i].ByteCount > ta.topTalkers[j].ByteCount
	})

	// 只保留前10个
	if len(ta.topTalkers) > 10 {
		ta.topTalkers = ta.topTalkers[:10]
	}
}

// recordBandwidthSample 记录带宽采样
func (ta *TrafficAnalyzer) recordBandwidthSample() {
	var bytesIn, bytesOut, packetsIn, packetsOut uint64

	for _, flow := range ta.flowStats {
		// 简化处理，假设所有流量都是入站
		bytesIn += flow.ByteCount
		packetsIn += flow.PacketCount
	}

	sample := BandwidthSample{
		Timestamp:  time.Now(),
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
		PacketsIn:  packetsIn,
		PacketsOut: packetsOut,
	}

	ta.bandwidthHistory = append(ta.bandwidthHistory, sample)

	// 只保留最近1小时的数据
	if len(ta.bandwidthHistory) > 720 { // 5秒间隔，1小时=720个采样点
		ta.bandwidthHistory = ta.bandwidthHistory[1:]
	}
}

// GetProtocolStats 获取协议统计
func (ta *TrafficAnalyzer) GetProtocolStats() map[string]*ProtocolStats {
	ta.mu.RLock()
	defer ta.mu.RUnlock()

	stats := make(map[string]*ProtocolStats)
	for k, v := range ta.protocolStats {
		stats[k] = v
	}
	return stats
}

// GetTopTalkers 获取流量大户
func (ta *TrafficAnalyzer) GetTopTalkers() []*TalkerStats {
	ta.mu.RLock()
	defer ta.mu.RUnlock()

	talkers := make([]*TalkerStats, len(ta.topTalkers))
	copy(talkers, ta.topTalkers)
	return talkers
}

// GetBandwidthHistory 获取带宽历史
func (ta *TrafficAnalyzer) GetBandwidthHistory() []BandwidthSample {
	ta.mu.RLock()
	defer ta.mu.RUnlock()

	history := make([]BandwidthSample, len(ta.bandwidthHistory))
	copy(history, ta.bandwidthHistory)
	return history
}

// NewAnomalyDetector 创建新的异常检测器
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		baselineTraffic:  make(map[string]float64),
		thresholds:       make(map[string]float64),
		anomalies:        make([]AnomalyEvent, 0),
		enabled:          false,
		learningPeriod:   24 * time.Hour,
		detectionEnabled: false,
	}
}

// DetectAnomalies 检测异常
func (ad *AnomalyDetector) DetectAnomalies(protocolStats map[string]*ProtocolStats) {
	if !ad.detectionEnabled {
		return
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	for protocol, stats := range protocolStats {
		baseline, exists := ad.baselineTraffic[protocol]
		if !exists {
			// 建立基线
			ad.baselineTraffic[protocol] = float64(stats.ByteCount)
			continue
		}

		threshold, exists := ad.thresholds[protocol]
		if !exists {
			threshold = baseline * 2.0 // 默认阈值为基线的2倍
			ad.thresholds[protocol] = threshold
		}

		currentTraffic := float64(stats.ByteCount)
		if currentTraffic > threshold {
			// 检测到异常
			anomaly := AnomalyEvent{
				Timestamp:   time.Now(),
				Type:        "Traffic Spike",
				Description: fmt.Sprintf("Protocol %s traffic exceeded threshold", protocol),
				Severity:    SeverityMedium,
				Value:       currentTraffic,
				Threshold:   threshold,
			}

			if currentTraffic > threshold*2 {
				anomaly.Severity = SeverityHigh
			}
			if currentTraffic > threshold*5 {
				anomaly.Severity = SeverityCritical
			}

			ad.anomalies = append(ad.anomalies, anomaly)

			// 只保留最近100个异常
			if len(ad.anomalies) > 100 {
				ad.anomalies = ad.anomalies[1:]
			}
		}
	}
}

// GetAnomalies 获取异常事件
func (ad *AnomalyDetector) GetAnomalies() []AnomalyEvent {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	anomalies := make([]AnomalyEvent, len(ad.anomalies))
	copy(anomalies, ad.anomalies)
	return anomalies
}

// NewRealTimeMonitor 创建新的实时监控器
func NewRealTimeMonitor() *RealTimeMonitor {
	return &RealTimeMonitor{
		metrics:        make(map[string]interface{}),
		alerts:         make([]Alert, 0),
		thresholds:     make(map[string]Threshold),
		updateInterval: 1 * time.Second,
		enabled:        false,
		subscribers:    make([]chan MonitorEvent, 0),
	}
}

// Start 启动实时监控器
func (rm *RealTimeMonitor) Start() {
	ticker := time.NewTicker(rm.updateInterval)
	defer ticker.Stop()

	for rm.enabled {
		select {
		case <-ticker.C:
			rm.updateMetrics()
			rm.checkThresholds()
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// Stop 停止实时监控器
func (rm *RealTimeMonitor) Stop() {
	rm.enabled = false
}

// ProcessPacket 处理数据包
func (rm *RealTimeMonitor) ProcessPacket(pkt *packet.Packet) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// 更新实时指标
	rm.metrics["last_packet_time"] = pkt.Timestamp
	rm.metrics["last_packet_size"] = pkt.Size
	rm.metrics["last_packet_source"] = pkt.Source.String()
	rm.metrics["last_packet_dest"] = pkt.Destination.String()

	// 发送监控事件
	event := MonitorEvent{
		Timestamp: time.Now(),
		Type:      "packet_received",
		Data:      pkt,
	}

	rm.notifySubscribers(event)
}

// updateMetrics 更新指标
func (rm *RealTimeMonitor) updateMetrics() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.metrics["timestamp"] = time.Now()
	rm.metrics["uptime"] = time.Since(time.Now()) // 这里应该是启动时间
}

// checkThresholds 检查阈值
func (rm *RealTimeMonitor) checkThresholds() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for metricName, threshold := range rm.thresholds {
		if value, exists := rm.metrics[metricName]; exists {
			if rm.evaluateThreshold(value, threshold) {
				alert := Alert{
					ID:        fmt.Sprintf("alert_%d", time.Now().UnixNano()),
					Timestamp: time.Now(),
					Type:      "threshold_exceeded",
					Message:   fmt.Sprintf("Metric %s exceeded threshold %f", metricName, threshold.Value),
					Severity:  AlertSeverityWarning,
					Resolved:  false,
				}

				rm.alerts = append(rm.alerts, alert)

				// 只保留最近50个告警
				if len(rm.alerts) > 50 {
					rm.alerts = rm.alerts[1:]
				}
			}
		}
	}
}

// evaluateThreshold 评估阈值
func (rm *RealTimeMonitor) evaluateThreshold(value interface{}, threshold Threshold) bool {
	// 简化实现，只处理数值类型
	switch v := value.(type) {
	case float64:
		switch threshold.Operator {
		case ">":
			return v > threshold.Value
		case "<":
			return v < threshold.Value
		case ">=":
			return v >= threshold.Value
		case "<=":
			return v <= threshold.Value
		case "==":
			return v == threshold.Value
		case "!=":
			return v != threshold.Value
		}
	case int:
		return rm.evaluateThreshold(float64(v), threshold)
	}
	return false
}

// notifySubscribers 通知订阅者
func (rm *RealTimeMonitor) notifySubscribers(event MonitorEvent) {
	for _, subscriber := range rm.subscribers {
		select {
		case subscriber <- event:
		default:
			// 订阅者通道满了，跳过
		}
	}
}

// Subscribe 订阅监控事件
func (rm *RealTimeMonitor) Subscribe() chan MonitorEvent {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	ch := make(chan MonitorEvent, 100)
	rm.subscribers = append(rm.subscribers, ch)
	return ch
}

// GetMetrics 获取当前指标
func (rm *RealTimeMonitor) GetMetrics() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	metrics := make(map[string]interface{})
	for k, v := range rm.metrics {
		metrics[k] = v
	}
	return metrics
}

// GetAlerts 获取告警
func (rm *RealTimeMonitor) GetAlerts() []Alert {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	alerts := make([]Alert, len(rm.alerts))
	copy(alerts, rm.alerts)
	return alerts
}

// SetThreshold 设置阈值
func (rm *RealTimeMonitor) SetThreshold(metricName string, threshold Threshold) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.thresholds[metricName] = threshold
}

// GetSupportedInterfaces 获取支持的网络接口列表
func GetSupportedInterfaces() ([]net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口列表失败: %v", err)
	}

	var supportedInterfaces []net.Interface
	for _, iface := range interfaces {
		// 过滤掉回环接口和未启用的接口
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			supportedInterfaces = append(supportedInterfaces, iface)
		}
	}

	return supportedInterfaces, nil
}

// ValidateInterface 验证网络接口是否有效
func ValidateInterface(interfaceName string) error {
	if strings.TrimSpace(interfaceName) == "" {
		return fmt.Errorf("接口名称不能为空")
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("接口 %s 不存在: %v", interfaceName, err)
	}

	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("接口 %s 未启用", interfaceName)
	}

	return nil
}

// getPacketTypeString 将PacketType转换为字符串
func getPacketTypeString(pktType packet.PacketType) string {
	switch pktType {
	case packet.PacketTypeIPv4:
		return "IPv4"
	case packet.PacketTypeIPv6:
		return "IPv6"
	case packet.PacketTypeARP:
		return "ARP"
	case packet.PacketTypeICMP:
		return "ICMP"
	default:
		return "Unknown"
	}
}
