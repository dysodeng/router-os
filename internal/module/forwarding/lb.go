package forwarding

import (
	"crypto/rand"
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"router-os/internal/module/routing"
	"sync"
	"time"
)

// LoadBalancer 负载均衡
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
	_, _ = rand.Read(randBytes)
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
	_, _ = rand.Read(randBytes)
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
