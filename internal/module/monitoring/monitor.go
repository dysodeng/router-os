package monitoring

import (
	"runtime"
	"sync"
	"time"

	"router-os/internal/module/interfaces"
	"router-os/internal/module/routing"
)

// SystemStats 系统统计信息
type SystemStats struct {
	Uptime           time.Duration `json:"uptime"`
	CPUUsage         float64       `json:"cpu_usage"`
	MemoryUsage      uint64        `json:"memory_usage"`
	MemoryTotal      uint64        `json:"memory_total"`
	GoroutineCount   int           `json:"goroutine_count"`
	PacketsReceived  uint64        `json:"packets_received"`
	PacketsSent      uint64        `json:"packets_sent"`
	BytesReceived    uint64        `json:"bytes_received"`
	BytesSent        uint64        `json:"bytes_sent"`
	RouteCount       int           `json:"route_count"`
	InterfaceCount   int           `json:"interface_count"`
	ActiveInterfaces int           `json:"active_interfaces"`
}

// Monitor 监控器
type Monitor struct {
	startTime        time.Time
	routingTable     routing.TableInterface
	interfaceManager *interfaces.Manager
	stats            SystemStats
	mu               sync.RWMutex
	running          bool
}

// NewMonitor 创建监控器
func NewMonitor(routingTable routing.TableInterface, interfaceManager *interfaces.Manager) *Monitor {
	return &Monitor{
		startTime:        time.Now(),
		routingTable:     routingTable,
		interfaceManager: interfaceManager,
		running:          false,
	}
}

// Start 启动监控
func (m *Monitor) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return
	}

	m.running = true
	go m.collectStats()
}

// Stop 停止监控
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = false
}

// collectStats 收集统计信息
func (m *Monitor) collectStats() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !m.IsRunning() {
			return
		}
		m.updateStats()
	}
}

// updateStats 更新统计信息
func (m *Monitor) updateStats() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 系统运行时间
	m.stats.Uptime = time.Since(m.startTime)

	// 内存使用情况
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.stats.MemoryUsage = memStats.Alloc
	m.stats.MemoryTotal = memStats.Sys

	// Goroutine数量
	m.stats.GoroutineCount = runtime.NumGoroutine()

	// 路由表统计
	m.stats.RouteCount = m.routingTable.Size()

	// 接口统计
	allInterfaces := m.interfaceManager.GetAllInterfaces()
	activeInterfaces := m.interfaceManager.GetActiveInterfaces()

	m.stats.InterfaceCount = len(allInterfaces)
	m.stats.ActiveInterfaces = len(activeInterfaces)

	// 网络流量统计
	var totalRxPackets, totalTxPackets, totalRxBytes, totalTxBytes uint64
	for _, iface := range allInterfaces {
		totalRxPackets += iface.RxPackets
		totalTxPackets += iface.TxPackets
		totalRxBytes += iface.RxBytes
		totalTxBytes += iface.TxBytes
	}

	m.stats.PacketsReceived = totalRxPackets
	m.stats.PacketsSent = totalTxPackets
	m.stats.BytesReceived = totalRxBytes
	m.stats.BytesSent = totalTxBytes
}

// GetStats 获取统计信息
func (m *Monitor) GetStats() SystemStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// IsRunning 检查监控是否在运行
func (m *Monitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// GetInterfaceStats 获取接口统计信息
func (m *Monitor) GetInterfaceStats() map[string]InterfaceStats {
	allInterfaces := m.interfaceManager.GetAllInterfaces()
	stats := make(map[string]InterfaceStats)

	for name, iface := range allInterfaces {
		stats[name] = InterfaceStats{
			Name:      iface.Name,
			Status:    iface.Status,
			RxPackets: iface.RxPackets,
			TxPackets: iface.TxPackets,
			RxBytes:   iface.RxBytes,
			TxBytes:   iface.TxBytes,
			Errors:    iface.Errors,
			LastSeen:  iface.LastSeen,
		}
	}

	return stats
}

// InterfaceStats 接口统计信息
type InterfaceStats struct {
	Name      string                     `json:"name"`
	Status    interfaces.InterfaceStatus `json:"status"`
	RxPackets uint64                     `json:"rx_packets"`
	TxPackets uint64                     `json:"tx_packets"`
	RxBytes   uint64                     `json:"rx_bytes"`
	TxBytes   uint64                     `json:"tx_bytes"`
	Errors    uint64                     `json:"errors"`
	LastSeen  time.Time                  `json:"last_seen"`
}

// GetRouteStats 获取路由统计信息
func (m *Monitor) GetRouteStats() RouteStats {
	routes := m.routingTable.GetAllRoutes()

	stats := RouteStats{
		Total:     len(routes),
		Static:    0,
		Dynamic:   0,
		Connected: 0,
		Default:   0,
	}

	for _, route := range routes {
		switch route.Type {
		case routing.RouteTypeStatic:
			stats.Static++
		case routing.RouteTypeDynamic:
			stats.Dynamic++
		case routing.RouteTypeConnected:
			stats.Connected++
		case routing.RouteTypeDefault:
			stats.Default++
		}
	}

	return stats
}

// RouteStats 路由统计信息
type RouteStats struct {
	Total     int `json:"total"`
	Static    int `json:"static"`
	Dynamic   int `json:"dynamic"`
	Connected int `json:"connected"`
	Default   int `json:"default"`
}

// GetMemoryUsagePercent 获取内存使用百分比
func (m *Monitor) GetMemoryUsagePercent() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.stats.MemoryTotal == 0 {
		return 0
	}

	return float64(m.stats.MemoryUsage) / float64(m.stats.MemoryTotal) * 100
}
