package routing

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// HealthMetrics 健康指标
type HealthMetrics struct {
	// Latency 延迟（毫秒）
	Latency float64

	// PacketLoss 丢包率（百分比）
	PacketLoss float64

	// BandwidthUtilization 带宽利用率（百分比）
	BandwidthUtilization float64

	// Jitter 抖动（毫秒）
	Jitter float64

	// Throughput 吞吐量（Mbps）
	Throughput float64

	// LastUpdate 最后更新时间
	LastUpdate time.Time

	// IsHealthy 是否健康
	IsHealthy bool
}

// HealthThresholds 健康阈值
type HealthThresholds struct {
	// MaxLatency 最大延迟（毫秒）
	MaxLatency float64

	// MaxPacketLoss 最大丢包率（百分比）
	MaxPacketLoss float64

	// MaxBandwidthUtilization 最大带宽利用率（百分比）
	MaxBandwidthUtilization float64

	// MaxJitter 最大抖动（毫秒）
	MaxJitter float64

	// MinThroughput 最小吞吐量（Mbps）
	MinThroughput float64
}

// DefaultHealthThresholds 默认健康阈值
var DefaultHealthThresholds = HealthThresholds{
	MaxLatency:              100.0, // 100ms
	MaxPacketLoss:           5.0,   // 5%
	MaxBandwidthUtilization: 80.0,  // 80%
	MaxJitter:               20.0,  // 20ms
	MinThroughput:           1.0,   // 1Mbps
}

// HealthMonitorConfig 健康监控配置
type HealthMonitorConfig struct {
	// Interval 检查间隔
	Interval time.Duration

	// Timeout 超时时间
	Timeout time.Duration

	// RetryCount 重试次数
	RetryCount int

	// Thresholds 健康阈值
	Thresholds HealthThresholds

	// Enabled 是否启用
	Enabled bool
}

// DefaultHealthMonitorConfig 默认健康监控配置
var DefaultHealthMonitorConfig = HealthMonitorConfig{
	Interval:   30 * time.Second,
	Timeout:    5 * time.Second,
	RetryCount: 3,
	Thresholds: DefaultHealthThresholds,
	Enabled:    true,
}

// HealthMonitor 健康监控器
type HealthMonitor struct {
	// routes 监控的路由
	routes map[string]*MonitoredRoute

	// config 配置
	config HealthMonitorConfig

	// mu 读写锁
	mu sync.RWMutex

	// ctx 上下文
	ctx context.Context

	// cancel 取消函数
	cancel context.CancelFunc

	// callbacks 健康状态变化回调
	callbacks []HealthChangeCallback
}

// MonitoredRoute 被监控的路由
type MonitoredRoute struct {
	// Route 路由信息
	Route *Route

	// Metrics 健康指标
	Metrics HealthMetrics

	// LastCheck 最后检查时间
	LastCheck time.Time

	// CheckCount 检查次数
	CheckCount int64

	// FailureCount 失败次数
	FailureCount int64
}

// HealthChangeCallback 健康状态变化回调
type HealthChangeCallback func(routeID string, oldHealth, newHealth bool, metrics HealthMetrics)

// NewHealthMonitor 创建健康监控器
func NewHealthMonitor(config HealthMonitorConfig) *HealthMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	hm := &HealthMonitor{
		routes:    make(map[string]*MonitoredRoute),
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		callbacks: make([]HealthChangeCallback, 0),
	}

	if config.Enabled {
		go hm.startMonitoring()
	}

	return hm
}

// AddRoute 添加监控路由
func (hm *HealthMonitor) AddRoute(route *Route) error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	routeID := route.Destination.String()

	monitoredRoute := &MonitoredRoute{
		Route: route,
		Metrics: HealthMetrics{
			LastUpdate: time.Now(),
			IsHealthy:  true,
		},
		LastCheck:    time.Now(),
		CheckCount:   0,
		FailureCount: 0,
	}

	hm.routes[routeID] = monitoredRoute

	return nil
}

// RemoveRoute 移除监控路由
func (hm *HealthMonitor) RemoveRoute(routeID string) error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	delete(hm.routes, routeID)

	return nil
}

// GetMetrics 获取路由健康指标
func (hm *HealthMonitor) GetMetrics(routeID string) (HealthMetrics, error) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	route, exists := hm.routes[routeID]
	if !exists {
		return HealthMetrics{}, fmt.Errorf("route not found: %s", routeID)
	}

	return route.Metrics, nil
}

// GetAllMetrics 获取所有路由健康指标
func (hm *HealthMonitor) GetAllMetrics() map[string]HealthMetrics {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	metrics := make(map[string]HealthMetrics)
	for routeID, route := range hm.routes {
		metrics[routeID] = route.Metrics
	}

	return metrics
}

// AddHealthChangeCallback 添加健康状态变化回调
func (hm *HealthMonitor) AddHealthChangeCallback(callback HealthChangeCallback) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.callbacks = append(hm.callbacks, callback)
}

// startMonitoring 开始监控
func (hm *HealthMonitor) startMonitoring() {
	ticker := time.NewTicker(hm.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-hm.ctx.Done():
			return
		case <-ticker.C:
			hm.performHealthChecks()
		}
	}
}

// performHealthChecks 执行健康检查
func (hm *HealthMonitor) performHealthChecks() {
	hm.mu.Lock()
	routes := make([]*MonitoredRoute, 0, len(hm.routes))
	for _, route := range hm.routes {
		routes = append(routes, route)
	}
	hm.mu.Unlock()

	// 并发检查所有路由
	var wg sync.WaitGroup
	for _, route := range routes {
		wg.Add(1)
		go func(mr *MonitoredRoute) {
			defer wg.Done()
			hm.checkRouteHealth(mr)
		}(route)
	}

	wg.Wait()
}

// checkRouteHealth 检查单个路由健康状态
func (hm *HealthMonitor) checkRouteHealth(route *MonitoredRoute) {
	routeID := route.Route.Destination.String()
	oldHealth := route.Metrics.IsHealthy

	// 执行健康检查
	metrics := hm.performHealthCheck(route.Route)

	// 更新指标
	hm.mu.Lock()
	route.Metrics = metrics
	route.LastCheck = time.Now()
	route.CheckCount++

	if !metrics.IsHealthy {
		route.FailureCount++
	}
	hm.mu.Unlock()

	// 如果健康状态发生变化，触发回调
	if oldHealth != metrics.IsHealthy {
		for _, callback := range hm.callbacks {
			go callback(routeID, oldHealth, metrics.IsHealthy, metrics)
		}
	}
}

// performHealthCheck 执行健康检查
func (hm *HealthMonitor) performHealthCheck(route *Route) HealthMetrics {
	metrics := HealthMetrics{
		LastUpdate: time.Now(),
		IsHealthy:  true,
	}

	// 检查延迟
	latency := hm.measureLatency(route.Gateway)
	metrics.Latency = latency

	// 检查丢包率
	packetLoss := hm.measurePacketLoss(route.Gateway)
	metrics.PacketLoss = packetLoss

	// 检查带宽利用率
	bandwidthUtil := hm.measureBandwidthUtilization(route.Interface)
	metrics.BandwidthUtilization = bandwidthUtil

	// 检查抖动
	jitter := hm.measureJitter(route.Gateway)
	metrics.Jitter = jitter

	// 检查吞吐量
	throughput := hm.measureThroughput(route.Interface)
	metrics.Throughput = throughput

	// 判断是否健康
	metrics.IsHealthy = hm.evaluateHealth(metrics)

	return metrics
}

// measureLatency 测量延迟
func (hm *HealthMonitor) measureLatency(gateway net.IP) float64 {
	// 简化实现：使用ping测量延迟
	start := time.Now()

	// 模拟ping操作
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", gateway.String()), hm.config.Timeout)
	if err != nil {
		return 1000.0 // 返回高延迟表示不可达
	}
	defer conn.Close()

	latency := time.Since(start).Seconds() * 1000 // 转换为毫秒
	return latency
}

// measurePacketLoss 测量丢包率
func (hm *HealthMonitor) measurePacketLoss(gateway net.IP) float64 {
	// 简化实现：基于连接成功率估算丢包率
	successCount := 0
	totalCount := 5

	for i := 0; i < totalCount; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", gateway.String()), hm.config.Timeout)
		if err == nil {
			successCount++
			conn.Close()
		}
	}

	packetLoss := float64(totalCount-successCount) / float64(totalCount) * 100
	return packetLoss
}

// measureBandwidthUtilization 测量带宽利用率
func (hm *HealthMonitor) measureBandwidthUtilization(interfaceName string) float64 {
	// 简化实现：返回模拟值
	// 实际实现需要读取网络接口统计信息
	return 50.0 // 50%
}

// measureJitter 测量抖动
func (hm *HealthMonitor) measureJitter(gateway net.IP) float64 {
	// 简化实现：测量多次延迟的标准差
	latencies := make([]float64, 3)
	for i := 0; i < 3; i++ {
		latencies[i] = hm.measureLatency(gateway)
	}

	// 计算平均值
	var sum float64
	for _, latency := range latencies {
		sum += latency
	}
	avg := sum / float64(len(latencies))

	// 计算标准差
	var variance float64
	for _, latency := range latencies {
		variance += (latency - avg) * (latency - avg)
	}
	variance /= float64(len(latencies))

	jitter := variance // 简化为方差
	return jitter
}

// measureThroughput 测量吞吐量
func (hm *HealthMonitor) measureThroughput(interfaceName string) float64 {
	// 简化实现：返回模拟值
	// 实际实现需要测量实际数据传输速率
	return 100.0 // 100Mbps
}

// evaluateHealth 评估健康状态
func (hm *HealthMonitor) evaluateHealth(metrics HealthMetrics) bool {
	thresholds := hm.config.Thresholds

	if metrics.Latency > thresholds.MaxLatency {
		return false
	}

	if metrics.PacketLoss > thresholds.MaxPacketLoss {
		return false
	}

	if metrics.BandwidthUtilization > thresholds.MaxBandwidthUtilization {
		return false
	}

	if metrics.Jitter > thresholds.MaxJitter {
		return false
	}

	if metrics.Throughput < thresholds.MinThroughput {
		return false
	}

	return true
}

// Stop 停止监控
func (hm *HealthMonitor) Stop() {
	hm.cancel()
}

// GetStats 获取监控统计信息
func (hm *HealthMonitor) GetStats() map[string]interface{} {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	stats := make(map[string]interface{})

	totalRoutes := len(hm.routes)
	healthyRoutes := 0
	totalChecks := int64(0)
	totalFailures := int64(0)

	for _, route := range hm.routes {
		if route.Metrics.IsHealthy {
			healthyRoutes++
		}
		totalChecks += route.CheckCount
		totalFailures += route.FailureCount
	}

	stats["total_routes"] = totalRoutes
	stats["healthy_routes"] = healthyRoutes
	stats["unhealthy_routes"] = totalRoutes - healthyRoutes
	stats["total_checks"] = totalChecks
	stats["total_failures"] = totalFailures

	if totalChecks > 0 {
		stats["failure_rate"] = float64(totalFailures) / float64(totalChecks) * 100
	} else {
		stats["failure_rate"] = 0.0
	}

	return stats
}
