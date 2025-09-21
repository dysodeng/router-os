package routing

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// FailoverPolicy 故障转移策略
type FailoverPolicy int

const (
	// ActivePassive 主备模式
	// 特点：只有主路由处理流量，备路由待机
	// 优点：简单可靠，资源利用率低
	// 缺点：备用资源浪费
	// 适用场景：对一致性要求高的场景
	ActivePassive FailoverPolicy = iota

	// ActiveActive 主主模式
	// 特点：多个路由同时处理流量，负载分担
	// 优点：资源利用率高，性能好
	// 缺点：复杂度高，需要负载均衡
	// 适用场景：高并发场景
	ActiveActive

	// PriorityBased 优先级模式
	// 特点：按优先级顺序使用路由
	// 优点：灵活可控，支持多级备份
	// 缺点：配置复杂
	// 适用场景：有明确优先级要求的场景
	PriorityBased
)

// HealthCheckType 健康检查类型
type HealthCheckType int

const (
	// PingCheck ICMP Ping检查
	// 特点：检查网络连通性
	// 优点：简单快速，开销小
	// 缺点：只能检查网络层连通性
	// 适用场景：基本网络连通性检查
	PingCheck HealthCheckType = iota

	// TCPCheck TCP连接检查
	// 特点：检查TCP端口连通性
	// 优点：检查传输层连通性
	// 缺点：开销较大
	// 适用场景：服务端口检查
	TCPCheck

	// HTTPCheck HTTP健康检查
	// 特点：检查HTTP服务状态
	// 优点：检查应用层服务状态
	// 缺点：开销最大，需要HTTP服务
	// 适用场景：Web服务健康检查
	HTTPCheck

	// CustomCheck 自定义检查
	// 特点：用户自定义检查逻辑
	// 优点：灵活性最高
	// 缺点：需要用户实现
	// 适用场景：特殊业务需求
	CustomCheck
)

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	// Type 检查类型
	Type HealthCheckType

	// Interval 检查间隔
	Interval time.Duration

	// Timeout 检查超时时间
	Timeout time.Duration

	// Retries 重试次数
	Retries int

	// FailureThreshold 失败阈值（连续失败多少次标记为不健康）
	FailureThreshold int

	// SuccessThreshold 成功阈值（连续成功多少次标记为健康）
	SuccessThreshold int

	// Target 检查目标（IP地址或URL）
	Target string

	// Port 检查端口（用于TCP/HTTP检查）
	Port int

	// Path HTTP检查路径（用于HTTP检查）
	Path string

	// ExpectedStatus 期望的HTTP状态码（用于HTTP检查）
	ExpectedStatus int

	// CustomChecker 自定义检查函数
	CustomChecker func(target string) error
}

// FailoverRoute 故障转移路由
type FailoverRoute struct {
	*LoadBalancedRoute

	// Priority 优先级（数字越小优先级越高）
	Priority int

	// IsActive 是否激活（用于主备模式）
	IsActive bool

	// HealthConfig 健康检查配置
	HealthConfig HealthCheckConfig

	// LastFailoverTime 最后一次故障转移时间
	LastFailoverTime time.Time

	// FailoverCount 故障转移次数
	FailoverCount int

	// ConsecutiveFailures 连续失败次数
	ConsecutiveFailures int

	// ConsecutiveSuccesses 连续成功次数
	ConsecutiveSuccesses int
}

// FailoverManager 故障转移管理器
type FailoverManager struct {
	// policy 故障转移策略
	policy FailoverPolicy

	// routes 故障转移路由列表
	routes []*FailoverRoute

	// activeRoutes 当前激活的路由
	activeRoutes []*FailoverRoute

	// loadBalancer 负载均衡器（用于主主模式）
	loadBalancer *LoadBalancer

	// mu 读写锁
	mu sync.RWMutex

	// ctx 上下文
	ctx context.Context

	// cancel 取消函数
	cancel context.CancelFunc

	// healthCheckInterval 健康检查间隔
	healthCheckInterval time.Duration

	// destination 目标网络
	destination *net.IPNet

	// stats 统计信息
	stats FailoverStats

	// eventChan 事件通道
	eventChan chan FailoverEvent
}

// FailoverStats 故障转移统计信息
type FailoverStats struct {
	// TotalFailovers 总故障转移次数
	TotalFailovers int64

	// LastFailoverTime 最后一次故障转移时间
	LastFailoverTime time.Time

	// ActiveRouteCount 当前激活路由数量
	ActiveRouteCount int

	// HealthyRouteCount 健康路由数量
	HealthyRouteCount int

	// TotalRouteCount 总路由数量
	TotalRouteCount int

	// AverageFailoverTime 平均故障转移时间
	AverageFailoverTime time.Duration
}

// FailoverEvent 故障转移事件
type FailoverEvent struct {
	// Type 事件类型
	Type FailoverEventType

	// Route 相关路由
	Route *FailoverRoute

	// Timestamp 事件时间
	Timestamp time.Time

	// Message 事件消息
	Message string

	// Error 错误信息（如果有）
	Error error
}

// FailoverEventType 故障转移事件类型
type FailoverEventType int

const (
	// RouteHealthy 路由变为健康
	RouteHealthy FailoverEventType = iota

	// RouteUnhealthy 路由变为不健康
	RouteUnhealthy

	// RouteActivated 路由被激活
	RouteActivated

	// RouteDeactivated 路由被停用
	RouteDeactivated

	// FailoverTriggered 故障转移被触发
	FailoverTriggered

	// FailoverCompleted 故障转移完成
	FailoverCompleted
)

// NewFailoverManager 创建故障转移管理器
func NewFailoverManager(destination *net.IPNet, policy FailoverPolicy) *FailoverManager {
	ctx, cancel := context.WithCancel(context.Background())

	fm := &FailoverManager{
		policy:              policy,
		routes:              make([]*FailoverRoute, 0),
		activeRoutes:        make([]*FailoverRoute, 0),
		destination:         destination,
		ctx:                 ctx,
		cancel:              cancel,
		healthCheckInterval: 30 * time.Second,
		stats:               FailoverStats{},
		eventChan:           make(chan FailoverEvent, 100),
	}

	// 如果是主主模式，创建负载均衡器
	if policy == ActiveActive {
		fm.loadBalancer = NewLoadBalancer(destination, RoundRobin)
	}

	return fm
}

// AddRoute 添加故障转移路由
func (fm *FailoverManager) AddRoute(route Route, priority int, healthConfig HealthCheckConfig) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// 验证路由目标是否匹配
	if !fm.destination.IP.Equal(route.Destination.IP) ||
		fm.destination.Mask.String() != route.Destination.Mask.String() {
		return fmt.Errorf("route destination %v does not match failover destination %v",
			route.Destination, fm.destination)
	}

	// 创建负载均衡路由
	lbRoute := &LoadBalancedRoute{
		Route:              route,
		Weight:             1,
		CurrentConnections: 0,
		TotalConnections:   0,
		IsHealthy:          true,
		LastHealthCheck:    time.Now(),
		ResponseTime:       0,
		FailureCount:       0,
	}

	// 创建故障转移路由
	failoverRoute := &FailoverRoute{
		LoadBalancedRoute:    lbRoute,
		Priority:             priority,
		IsActive:             false,
		HealthConfig:         healthConfig,
		LastFailoverTime:     time.Time{},
		FailoverCount:        0,
		ConsecutiveFailures:  0,
		ConsecutiveSuccesses: 0,
	}

	fm.routes = append(fm.routes, failoverRoute)
	fm.stats.TotalRouteCount++

	// 根据策略激活路由
	fm.updateActiveRoutes()

	// 启动健康检查
	go fm.startHealthCheck(failoverRoute)

	return nil
}

// RemoveRoute 移除故障转移路由
func (fm *FailoverManager) RemoveRoute(gateway net.IP, iface string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	for i, route := range fm.routes {
		if route.Gateway.Equal(gateway) && route.Interface == iface {
			// 移除路由
			fm.routes = append(fm.routes[:i], fm.routes[i+1:]...)
			fm.stats.TotalRouteCount--

			// 更新激活路由
			fm.updateActiveRoutes()

			return nil
		}
	}

	return fmt.Errorf("route not found: gateway=%v, interface=%s", gateway, iface)
}

// SelectRoute 选择路由
func (fm *FailoverManager) SelectRoute(clientIP net.IP) (*FailoverRoute, error) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	if len(fm.activeRoutes) == 0 {
		return nil, fmt.Errorf("no active routes available")
	}

	switch fm.policy {
	case ActivePassive:
		// 返回第一个激活的路由
		return fm.activeRoutes[0], nil

	case ActiveActive:
		// 使用负载均衡器选择路由
		if fm.loadBalancer != nil {
			lbRoute, err := fm.loadBalancer.SelectRoute(clientIP)
			if err != nil {
				return nil, err
			}

			// 找到对应的故障转移路由
			for _, route := range fm.activeRoutes {
				if route.LoadBalancedRoute == lbRoute {
					return route, nil
				}
			}
		}

		// 如果负载均衡器不可用，使用轮询
		return fm.activeRoutes[0], nil

	case PriorityBased:
		// 返回优先级最高的健康路由
		for _, route := range fm.activeRoutes {
			if route.IsHealthy {
				return route, nil
			}
		}
		return nil, fmt.Errorf("no healthy routes available")

	default:
		return fm.activeRoutes[0], nil
	}
}

// updateActiveRoutes 更新激活路由列表
func (fm *FailoverManager) updateActiveRoutes() {
	fm.activeRoutes = make([]*FailoverRoute, 0)

	switch fm.policy {
	case ActivePassive:
		// 找到优先级最高的健康路由
		var primaryRoute *FailoverRoute
		for _, route := range fm.routes {
			if route.IsHealthy && (primaryRoute == nil || route.Priority < primaryRoute.Priority) {
				primaryRoute = route
			}
		}

		if primaryRoute != nil {
			primaryRoute.IsActive = true
			fm.activeRoutes = append(fm.activeRoutes, primaryRoute)
		}

		// 停用其他路由
		for _, route := range fm.routes {
			if route != primaryRoute {
				route.IsActive = false
			}
		}

	case ActiveActive:
		// 激活所有健康路由
		for _, route := range fm.routes {
			if route.IsHealthy {
				route.IsActive = true
				fm.activeRoutes = append(fm.activeRoutes, route)

				// 添加到负载均衡器
				if fm.loadBalancer != nil {
					_ = fm.loadBalancer.AddRoute(route.Route, route.Weight)
				}
			} else {
				route.IsActive = false
			}
		}

	case PriorityBased:
		// 按优先级排序，激活健康路由
		healthyRoutes := make([]*FailoverRoute, 0)
		for _, route := range fm.routes {
			if route.IsHealthy {
				healthyRoutes = append(healthyRoutes, route)
			}
		}

		// 按优先级排序
		for i := 0; i < len(healthyRoutes); i++ {
			for j := i + 1; j < len(healthyRoutes); j++ {
				if healthyRoutes[i].Priority > healthyRoutes[j].Priority {
					healthyRoutes[i], healthyRoutes[j] = healthyRoutes[j], healthyRoutes[i]
				}
			}
		}

		// 激活所有健康路由
		for _, route := range healthyRoutes {
			route.IsActive = true
			fm.activeRoutes = append(fm.activeRoutes, route)
		}

		// 停用不健康路由
		for _, route := range fm.routes {
			if !route.IsHealthy {
				route.IsActive = false
			}
		}
	}

	fm.stats.ActiveRouteCount = len(fm.activeRoutes)
}

// startHealthCheck 启动健康检查
func (fm *FailoverManager) startHealthCheck(route *FailoverRoute) {
	ticker := time.NewTicker(route.HealthConfig.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-fm.ctx.Done():
			return
		case <-ticker.C:
			fm.performHealthCheck(route)
		}
	}
}

// performHealthCheck 执行健康检查
func (fm *FailoverManager) performHealthCheck(route *FailoverRoute) {
	start := time.Now()
	var err error

	switch route.HealthConfig.Type {
	case PingCheck:
		err = fm.performPingCheck(route.HealthConfig.Target)
	case TCPCheck:
		err = fm.performTCPCheck(route.HealthConfig.Target, route.HealthConfig.Port)
	case HTTPCheck:
		err = fm.performHTTPCheck(route.HealthConfig.Target, route.HealthConfig.Port, route.HealthConfig.Path)
	case CustomCheck:
		if route.HealthConfig.CustomChecker != nil {
			err = route.HealthConfig.CustomChecker(route.HealthConfig.Target)
		}
	}

	responseTime := time.Since(start)
	route.ResponseTime = responseTime
	route.LastHealthCheck = time.Now()

	fm.mu.Lock()
	defer fm.mu.Unlock()

	wasHealthy := route.IsHealthy

	if err != nil {
		route.ConsecutiveFailures++
		route.ConsecutiveSuccesses = 0

		if route.ConsecutiveFailures >= route.HealthConfig.FailureThreshold {
			route.IsHealthy = false
		}

		// 发送事件
		if wasHealthy && !route.IsHealthy {
			fm.sendEvent(FailoverEvent{
				Type:      RouteUnhealthy,
				Route:     route,
				Timestamp: time.Now(),
				Message:   fmt.Sprintf("Route became unhealthy: %v", err),
				Error:     err,
			})
		}
	} else {
		route.ConsecutiveSuccesses++
		route.ConsecutiveFailures = 0

		if route.ConsecutiveSuccesses >= route.HealthConfig.SuccessThreshold {
			route.IsHealthy = true
		}

		// 发送事件
		if !wasHealthy && route.IsHealthy {
			fm.sendEvent(FailoverEvent{
				Type:      RouteHealthy,
				Route:     route,
				Timestamp: time.Now(),
				Message:   "Route became healthy",
			})
		}
	}

	// 如果健康状态发生变化，更新激活路由
	if wasHealthy != route.IsHealthy {
		fm.updateActiveRoutes()
		fm.stats.HealthyRouteCount = fm.getHealthyRouteCount()

		if !route.IsHealthy {
			fm.stats.TotalFailovers++
			fm.stats.LastFailoverTime = time.Now()
			route.FailoverCount++
			route.LastFailoverTime = time.Now()
		}
	}
}

// performPingCheck 执行Ping检查
func (fm *FailoverManager) performPingCheck(target string) error {
	// 简化的ping检查实现
	// 在实际实现中，可以使用golang.org/x/net/icmp包
	conn, err := net.DialTimeout("ip4:icmp", target, 3*time.Second)
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()
	return nil
}

// performTCPCheck 执行TCP检查
func (fm *FailoverManager) performTCPCheck(target string, port int) error {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()
	return nil
}

// performHTTPCheck 执行HTTP检查
func (fm *FailoverManager) performHTTPCheck(target string, port int, path string) error {
	// 简化的HTTP检查实现
	// 在实际实现中，可以使用net/http包
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()
	return nil
}

// getHealthyRouteCount 获取健康路由数量
func (fm *FailoverManager) getHealthyRouteCount() int {
	count := 0
	for _, route := range fm.routes {
		if route.IsHealthy {
			count++
		}
	}
	return count
}

// sendEvent 发送事件
func (fm *FailoverManager) sendEvent(event FailoverEvent) {
	select {
	case fm.eventChan <- event:
	default:
		// 事件通道满了，丢弃事件
	}
}

// GetEventChannel 获取事件通道
func (fm *FailoverManager) GetEventChannel() <-chan FailoverEvent {
	return fm.eventChan
}

// GetStats 获取统计信息
func (fm *FailoverManager) GetStats() FailoverStats {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	fm.stats.HealthyRouteCount = fm.getHealthyRouteCount()
	return fm.stats
}

// GetRoutes 获取所有路由
func (fm *FailoverManager) GetRoutes() []*FailoverRoute {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	routes := make([]*FailoverRoute, len(fm.routes))
	copy(routes, fm.routes)
	return routes
}

// GetActiveRoutes 获取激活路由
func (fm *FailoverManager) GetActiveRoutes() []*FailoverRoute {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	routes := make([]*FailoverRoute, len(fm.activeRoutes))
	copy(routes, fm.activeRoutes)
	return routes
}

// Stop 停止故障转移管理器
func (fm *FailoverManager) Stop() {
	fm.cancel()
	close(fm.eventChan)
}

// String 返回故障转移策略的字符串表示
func (policy FailoverPolicy) String() string {
	switch policy {
	case ActivePassive:
		return "ActivePassive"
	case ActiveActive:
		return "ActiveActive"
	case PriorityBased:
		return "PriorityBased"
	default:
		return "Unknown"
	}
}

// String 返回健康检查类型的字符串表示
func (hct HealthCheckType) String() string {
	switch hct {
	case PingCheck:
		return "PingCheck"
	case TCPCheck:
		return "TCPCheck"
	case HTTPCheck:
		return "HTTPCheck"
	case CustomCheck:
		return "CustomCheck"
	default:
		return "Unknown"
	}
}
