package forwarding

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

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
	// 读取/proc/stat获取CPU使用率
	if runtime.GOOS == "linux" {
		return mc.getCPUUsageLinux()
	}
	// macOS使用runtime包获取基本信息
	return mc.getCPUUsageMacOS()
}

func (mc *MetricsCollector) getCPUUsageLinux() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0.0
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0.0
	}

	// 解析第一行CPU总体统计
	fields := strings.Fields(lines[0])
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0.0
	}

	// 计算CPU使用率：user + nice + system / total
	user, _ := strconv.ParseUint(fields[1], 10, 64)
	nice, _ := strconv.ParseUint(fields[2], 10, 64)
	system, _ := strconv.ParseUint(fields[3], 10, 64)
	idle, _ := strconv.ParseUint(fields[4], 10, 64)
	iowait, _ := strconv.ParseUint(fields[5], 10, 64)
	irq, _ := strconv.ParseUint(fields[6], 10, 64)
	softirq, _ := strconv.ParseUint(fields[7], 10, 64)

	total := user + nice + system + idle + iowait + irq + softirq
	used := user + nice + system + irq + softirq

	if total == 0 {
		return 0.0
	}

	return float64(used) / float64(total)
}

func (mc *MetricsCollector) getCPUUsageMacOS() float64 {
	// 在macOS上使用runtime.NumGoroutine()作为负载指示器
	// 这是一个简化的实现，真实环境中可以使用系统调用
	numGoroutines := runtime.NumGoroutine()
	numCPU := runtime.NumCPU()

	// 基于goroutine数量估算CPU使用率
	usage := float64(numGoroutines) / float64(numCPU*100)
	if usage > 1.0 {
		usage = 1.0
	}

	return usage
}

func (mc *MetricsCollector) getMemoryUsage() float64 {
	// 读取系统内存信息
	if runtime.GOOS == "linux" {
		return mc.getMemoryUsageLinux()
	}
	// macOS使用runtime包获取Go程序内存使用
	return mc.getMemoryUsageMacOS()
}

func (mc *MetricsCollector) getMemoryUsageLinux() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0.0
	}

	lines := strings.Split(string(data), "\n")
	var memTotal, memFree, memAvailable uint64

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "MemTotal:":
			memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemFree:":
			memFree, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemAvailable:":
			memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}

	if memTotal == 0 {
		return 0.0
	}

	// 优先使用MemAvailable，否则使用MemFree
	available := memAvailable
	if available == 0 {
		available = memFree
	}

	used := memTotal - available
	return float64(used) / float64(memTotal)
}

func (mc *MetricsCollector) getMemoryUsageMacOS() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 使用Go程序的内存使用情况作为指示器
	// 在真实环境中，可以使用系统调用获取系统总内存
	totalAlloc := m.TotalAlloc
	sys := m.Sys

	if sys == 0 {
		return 0.0
	}

	// 简化计算：已分配内存 / 系统内存
	usage := float64(totalAlloc) / float64(sys)
	if usage > 1.0 {
		usage = 1.0
	}

	return usage
}

func (mc *MetricsCollector) getNetworkIO() map[string]uint64 {
	// 读取网络接口统计信息
	if runtime.GOOS == "linux" {
		return mc.getNetworkIOLinux()
	}
	// macOS的简化实现
	return mc.getNetworkIOMacOS()
}

func (mc *MetricsCollector) getNetworkIOLinux() map[string]uint64 {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return map[string]uint64{"bytes_in": 0, "bytes_out": 0}
	}

	lines := strings.Split(string(data), "\n")
	var totalBytesIn, totalBytesOut uint64

	// 跳过前两行标题
	for i := 2; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// 解析接口统计信息
		parts := strings.Fields(line)
		if len(parts) < 10 {
			continue
		}

		// 跳过loopback接口
		interfaceName := strings.TrimSuffix(parts[0], ":")
		if interfaceName == "lo" {
			continue
		}

		// 接收字节数（第2列）和发送字节数（第10列）
		bytesIn, _ := strconv.ParseUint(parts[1], 10, 64)
		bytesOut, _ := strconv.ParseUint(parts[9], 10, 64)

		totalBytesIn += bytesIn
		totalBytesOut += bytesOut
	}

	return map[string]uint64{
		"bytes_in":  totalBytesIn,
		"bytes_out": totalBytesOut,
	}
}

func (mc *MetricsCollector) getNetworkIOMacOS() map[string]uint64 {
	// macOS的简化实现，使用时间戳生成模拟但相对稳定的数据
	// 在真实环境中，可以使用系统调用或执行netstat命令
	now := time.Now().Unix()

	// 基于时间生成相对稳定的网络IO数据
	bytesIn := uint64(now*1000 + int64(os.Getpid()))
	bytesOut := uint64(now*800 + int64(os.Getpid()*2))

	return map[string]uint64{
		"bytes_in":  bytesIn,
		"bytes_out": bytesOut,
	}
}

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
		_ = handler.HandleAlert(alert)
	}
}
