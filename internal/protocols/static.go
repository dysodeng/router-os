package protocols

import (
	"fmt"
	"net"

	"router-os/internal/routing"
)

// StaticRouteManager 静态路由管理器
type StaticRouteManager struct {
	routingTable routing.TableInterface
}

// NewStaticRouteManager 创建静态路由管理器
func NewStaticRouteManager(routingTable routing.TableInterface) *StaticRouteManager {
	return &StaticRouteManager{
		routingTable: routingTable,
	}
}

// AddStaticRoute 添加静态路由
func (srm *StaticRouteManager) AddStaticRoute(destination string, gateway string, iface string, metric int) error {
	// 解析目标网络
	_, destNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("无效的目标网络: %v", err)
	}

	// 解析网关
	gatewayIP := net.ParseIP(gateway)
	if gatewayIP == nil {
		return fmt.Errorf("无效的网关地址: %s", gateway)
	}

	// 创建路由条目
	route := routing.Route{
		Destination: destNet,
		Gateway:     gatewayIP,
		Interface:   iface,
		Metric:      metric,
		Type:        routing.RouteTypeStatic,
		TTL:         0, // 静态路由不过期
	}

	// 添加到路由表
	return srm.routingTable.AddRoute(route)
}

// RemoveStaticRoute 删除静态路由
func (srm *StaticRouteManager) RemoveStaticRoute(destination string, gateway string, iface string) error {
	// 解析目标网络
	_, destNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("无效的目标网络: %v", err)
	}

	// 解析网关
	gatewayIP := net.ParseIP(gateway)
	if gatewayIP == nil {
		return fmt.Errorf("无效的网关地址: %s", gateway)
	}

	return srm.routingTable.RemoveRoute(destNet, gatewayIP, iface)
}

// AddDefaultRoute 添加默认路由
func (srm *StaticRouteManager) AddDefaultRoute(gateway string, iface string, metric int) error {
	// 创建默认路由 (0.0.0.0/0)
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")

	gatewayIP := net.ParseIP(gateway)
	if gatewayIP == nil {
		return fmt.Errorf("无效的网关地址: %s", gateway)
	}

	route := routing.Route{
		Destination: defaultNet,
		Gateway:     gatewayIP,
		Interface:   iface,
		Metric:      metric,
		Proto:       "static",
		Scope:       "global",
		Src:         nil,
		Flags:       "default",
		Type:        routing.RouteTypeDefault,
		TTL:         0,
	}

	return srm.routingTable.AddRoute(route)
}

// GetStaticRoutes 获取所有静态路由
func (srm *StaticRouteManager) GetStaticRoutes() []routing.Route {
	allRoutes := srm.routingTable.GetAllRoutes()
	var staticRoutes []routing.Route

	for _, route := range allRoutes {
		if route.Type == routing.RouteTypeStatic || route.Type == routing.RouteTypeDefault {
			staticRoutes = append(staticRoutes, route)
		}
	}

	return staticRoutes
}
