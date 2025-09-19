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
