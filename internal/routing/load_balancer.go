package routing

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// LoadBalancingAlgorithm 负载均衡算法类型
type LoadBalancingAlgorithm int

const (
	// RoundRobin 轮询算法
	// 特点：按顺序依次选择下一个可用路由
	// 优点：简单公平，实现容易
	// 缺点：不考虑服务器负载差异
	// 适用场景：后端服务器性能相近的情况
	RoundRobin LoadBalancingAlgorithm = iota

	// WeightedRoundRobin 加权轮询算法
	// 特点：根据权重分配请求，权重高的路由获得更多请求
	// 优点：可以根据服务器性能分配负载
	// 缺点：静态权重，无法动态调整
	// 适用场景：后端服务器性能差异较大的情况
	WeightedRoundRobin

	// LeastConnections 最少连接算法
	// 特点：选择当前连接数最少的路由
	// 优点：动态负载均衡，适应实时负载变化
	// 缺点：需要维护连接状态，实现复杂
	// 适用场景：连接持续时间差异较大的情况
	LeastConnections

	// IPHash IP哈希算法
	// 特点：根据客户端IP计算哈希值，确保同一客户端总是路由到同一服务器
	// 优点：会话保持，状态一致性好
	// 缺点：负载可能不均衡
	// 适用场景：需要会话保持的应用
	IPHash
)

// LoadBalancedRoute 负载均衡路由条目
// 扩展了基本Route结构，添加了负载均衡相关的字段
type LoadBalancedRoute struct {
	Route

	// Weight 权重（用于加权轮询）
	// 取值范围：1-100，默认为1
	// 权重越高，获得的请求越多
	Weight int

	// CurrentConnections 当前连接数（用于最少连接算法）
	// 动态维护，每次建立连接时+1，断开连接时-1
	CurrentConnections int64

	// TotalConnections 总连接数（统计用）
	// 只增不减，用于统计该路由处理的总请求数
	TotalConnections int64

	// IsHealthy 健康状态
	// true表示路由可用，false表示路由不可用
	// 由健康检查机制维护
	IsHealthy bool

	// LastHealthCheck 最后一次健康检查时间
	LastHealthCheck time.Time

	// ResponseTime 平均响应时间（毫秒）
	// 用于性能监控和智能路由选择
	ResponseTime time.Duration

	// FailureCount 连续失败次数
	// 用于故障检测，超过阈值时标记为不健康
	FailureCount int
}

// LoadBalancer 负载均衡器
// 管理多个到达同一目标的路由，并根据算法选择最佳路由
type LoadBalancer struct {
	// algorithm 负载均衡算法
	algorithm LoadBalancingAlgorithm

	// routes 负载均衡路由列表
	// 所有路由都指向同一个目标网络，但通过不同的网关
	routes []*LoadBalancedRoute

	// currentIndex 当前轮询索引（用于轮询算法）
	currentIndex int64

	// weightedIndex 加权轮询索引
	weightedIndex int

	// weightedCurrentWeights 当前权重计数器
	weightedCurrentWeights []int

	// mu 读写锁，保护并发访问
	mu sync.RWMutex

	// destination 目标网络
	destination *net.IPNet

	// stats 统计信息
	stats LoadBalancerStats
}

// LoadBalancerStats 负载均衡器统计信息
type LoadBalancerStats struct {
	// TotalRequests 总请求数
	TotalRequests int64

	// SuccessfulRequests 成功请求数
	SuccessfulRequests int64

	// FailedRequests 失败请求数
	FailedRequests int64

	// AverageResponseTime 平均响应时间
	AverageResponseTime time.Duration

	// LastRequestTime 最后一次请求时间
	LastRequestTime time.Time
}

// NewLoadBalancer 创建新的负载均衡器
func NewLoadBalancer(destination *net.IPNet, algorithm LoadBalancingAlgorithm) *LoadBalancer {
	return &LoadBalancer{
		algorithm:   algorithm,
		routes:      make([]*LoadBalancedRoute, 0),
		destination: destination,
		stats:       LoadBalancerStats{},
	}
}

// AddRoute 添加负载均衡路由
func (lb *LoadBalancer) AddRoute(route Route, weight int) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	// 验证路由目标是否匹配
	if !lb.destination.IP.Equal(route.Destination.IP) ||
		lb.destination.Mask.String() != route.Destination.Mask.String() {
		return fmt.Errorf("route destination %v does not match load balancer destination %v",
			route.Destination, lb.destination)
	}

	// 创建负载均衡路由
	lbRoute := &LoadBalancedRoute{
		Route:              route,
		Weight:             weight,
		CurrentConnections: 0,
		TotalConnections:   0,
		IsHealthy:          true,
		LastHealthCheck:    time.Now(),
		ResponseTime:       0,
		FailureCount:       0,
	}

	lb.routes = append(lb.routes, lbRoute)

	// 初始化加权轮询权重
	if lb.algorithm == WeightedRoundRobin {
		lb.initWeightedRoundRobin()
	}

	return nil
}

// RemoveRoute 移除负载均衡路由
func (lb *LoadBalancer) RemoveRoute(gateway net.IP, iface string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for i, route := range lb.routes {
		if route.Gateway.Equal(gateway) && route.Interface == iface {
			// 移除路由
			lb.routes = append(lb.routes[:i], lb.routes[i+1:]...)

			// 重新初始化加权轮询权重
			if lb.algorithm == WeightedRoundRobin {
				lb.initWeightedRoundRobin()
			}

			return nil
		}
	}

	return fmt.Errorf("route not found: gateway=%v, interface=%s", gateway, iface)
}

// SelectRoute 根据负载均衡算法选择路由
func (lb *LoadBalancer) SelectRoute(clientIP net.IP) (*LoadBalancedRoute, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	// 过滤健康的路由
	healthyRoutes := make([]*LoadBalancedRoute, 0)
	for _, route := range lb.routes {
		if route.IsHealthy {
			healthyRoutes = append(healthyRoutes, route)
		}
	}

	if len(healthyRoutes) == 0 {
		return nil, fmt.Errorf("no healthy routes available")
	}

	// 更新统计信息
	atomic.AddInt64(&lb.stats.TotalRequests, 1)
	lb.stats.LastRequestTime = time.Now()

	// 根据算法选择路由
	switch lb.algorithm {
	case RoundRobin:
		return lb.selectRoundRobin(healthyRoutes), nil
	case WeightedRoundRobin:
		return lb.selectWeightedRoundRobin(healthyRoutes), nil
	case LeastConnections:
		return lb.selectLeastConnections(healthyRoutes), nil
	case IPHash:
		return lb.selectIPHash(healthyRoutes, clientIP), nil
	default:
		return healthyRoutes[0], nil
	}
}

// selectRoundRobin 轮询算法选择路由
func (lb *LoadBalancer) selectRoundRobin(routes []*LoadBalancedRoute) *LoadBalancedRoute {
	index := atomic.AddInt64(&lb.currentIndex, 1) % int64(len(routes))
	return routes[index]
}

// selectWeightedRoundRobin 加权轮询算法选择路由
func (lb *LoadBalancer) selectWeightedRoundRobin(routes []*LoadBalancedRoute) *LoadBalancedRoute {
	if len(lb.weightedCurrentWeights) != len(routes) {
		lb.initWeightedRoundRobin()
	}

	// 找到当前权重最大的路由
	maxWeight := -1
	selectedIndex := 0
	totalWeight := 0

	for i, route := range routes {
		lb.weightedCurrentWeights[i] += route.Weight
		totalWeight += route.Weight

		if lb.weightedCurrentWeights[i] > maxWeight {
			maxWeight = lb.weightedCurrentWeights[i]
			selectedIndex = i
		}
	}

	// 减少选中路由的当前权重
	lb.weightedCurrentWeights[selectedIndex] -= totalWeight

	return routes[selectedIndex]
}

// selectLeastConnections 最少连接算法选择路由
func (lb *LoadBalancer) selectLeastConnections(routes []*LoadBalancedRoute) *LoadBalancedRoute {
	minConnections := int64(^uint64(0) >> 1) // 最大int64值
	selectedRoute := routes[0]

	for _, route := range routes {
		connections := atomic.LoadInt64(&route.CurrentConnections)
		if connections < minConnections {
			minConnections = connections
			selectedRoute = route
		}
	}

	return selectedRoute
}

// selectIPHash IP哈希算法选择路由
func (lb *LoadBalancer) selectIPHash(routes []*LoadBalancedRoute, clientIP net.IP) *LoadBalancedRoute {
	// 简单的IP哈希实现
	hash := uint32(0)
	for _, b := range clientIP.To4() {
		hash = hash*31 + uint32(b)
	}

	index := hash % uint32(len(routes))
	return routes[index]
}

// initWeightedRoundRobin 初始化加权轮询权重
func (lb *LoadBalancer) initWeightedRoundRobin() {
	lb.weightedCurrentWeights = make([]int, len(lb.routes))
	for i := range lb.weightedCurrentWeights {
		lb.weightedCurrentWeights[i] = 0
	}
}

// IncrementConnections 增加连接计数
func (lb *LoadBalancer) IncrementConnections(gateway net.IP, iface string) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	for _, route := range lb.routes {
		if route.Gateway.Equal(gateway) && route.Interface == iface {
			atomic.AddInt64(&route.CurrentConnections, 1)
			atomic.AddInt64(&route.TotalConnections, 1)
			break
		}
	}
}

// DecrementConnections 减少连接计数
func (lb *LoadBalancer) DecrementConnections(gateway net.IP, iface string) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	for _, route := range lb.routes {
		if route.Gateway.Equal(gateway) && route.Interface == iface {
			if current := atomic.LoadInt64(&route.CurrentConnections); current > 0 {
				atomic.AddInt64(&route.CurrentConnections, -1)
			}
			break
		}
	}
}

// UpdateRouteHealth 更新路由健康状态
func (lb *LoadBalancer) UpdateRouteHealth(gateway net.IP, iface string, isHealthy bool, responseTime time.Duration) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for _, route := range lb.routes {
		if route.Gateway.Equal(gateway) && route.Interface == iface {
			route.IsHealthy = isHealthy
			route.LastHealthCheck = time.Now()
			route.ResponseTime = responseTime

			if isHealthy {
				route.FailureCount = 0
			} else {
				route.FailureCount++
			}
			break
		}
	}
}

// GetStats 获取负载均衡器统计信息
func (lb *LoadBalancer) GetStats() LoadBalancerStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	return lb.stats
}

// GetRoutes 获取所有路由信息
func (lb *LoadBalancer) GetRoutes() []*LoadBalancedRoute {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	// 返回副本以避免并发修改
	routes := make([]*LoadBalancedRoute, len(lb.routes))
	copy(routes, lb.routes)
	return routes
}

// GetHealthyRouteCount 获取健康路由数量
func (lb *LoadBalancer) GetHealthyRouteCount() int {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	count := 0
	for _, route := range lb.routes {
		if route.IsHealthy {
			count++
		}
	}
	return count
}

// SetAlgorithm 设置负载均衡算法
func (lb *LoadBalancer) SetAlgorithm(algorithm LoadBalancingAlgorithm) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.algorithm = algorithm

	// 重置相关状态
	lb.currentIndex = 0
	if algorithm == WeightedRoundRobin {
		lb.initWeightedRoundRobin()
	}
}

// String 返回负载均衡算法的字符串表示
func (alg LoadBalancingAlgorithm) String() string {
	switch alg {
	case RoundRobin:
		return "RoundRobin"
	case WeightedRoundRobin:
		return "WeightedRoundRobin"
	case LeastConnections:
		return "LeastConnections"
	case IPHash:
		return "IPHash"
	default:
		return "Unknown"
	}
}
