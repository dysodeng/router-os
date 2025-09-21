package forwarding

import (
	"fmt"
	"net"
	"time"
)

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
	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.lastCheck = time.Now()

	// 执行多种健康检查方法
	healthy := hc.performMultipleChecks()

	if !healthy {
		hc.failures++
		if hc.failures >= hc.threshold {
			hc.isHealthy = false
		}
	} else {
		hc.failures = 0
		hc.isHealthy = true
	}
}

// performMultipleChecks 执行多种健康检查
func (hc *HealthChecker) performMultipleChecks() bool {
	// 1. ICMP Ping 检查
	if hc.performICMPCheck() {
		return true
	}

	// 2. TCP 连接检查（多个常用端口）
	commonPorts := []int{80, 443, 22, 53}
	for _, port := range commonPorts {
		if hc.performTCPCheck(port) {
			return true
		}
	}

	// 3. UDP 检查（DNS）
	if hc.performUDPCheck(53) {
		return true
	}

	return false
}

// performICMPCheck 执行ICMP ping检查
func (hc *HealthChecker) performICMPCheck() bool {
	// 简化的ICMP检查实现
	// 在真实环境中，需要使用原始套接字发送ICMP包
	// 这里使用TCP连接作为替代方案

	// 尝试连接到目标的多个端口来模拟ping
	testPorts := []int{80, 443, 22}
	for _, port := range testPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", hc.target.String(), port), hc.timeout/3)
		if err == nil && conn != nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

// performTCPCheck 执行TCP连接检查
func (hc *HealthChecker) performTCPCheck(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", hc.target.String(), port), hc.timeout)
	if err != nil {
		return false
	}

	if conn != nil {
		_ = conn.Close()
		return true
	}

	return false
}

// performUDPCheck 执行UDP连接检查
func (hc *HealthChecker) performUDPCheck(port int) bool {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", hc.target.String(), port), hc.timeout)
	if err != nil {
		return false
	}

	if conn != nil {
		// 对于UDP，尝试发送一个简单的数据包
		_, err := conn.Write([]byte("health-check"))
		_ = conn.Close()

		// UDP连接不会立即报错，所以我们认为能建立连接就是成功
		return err == nil
	}

	return false
}
