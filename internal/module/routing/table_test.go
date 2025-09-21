package routing

import (
	"net"
	"testing"
)

func TestNewTable(t *testing.T) {
	table := NewTable()
	if table == nil {
		t.Fatal("NewTable() returned nil")
	}

	routes := table.GetAllRoutes()
	if len(routes) != 0 {
		t.Errorf("Expected empty routing table, got %d routes", len(routes))
	}
}

func TestAddRoute(t *testing.T) {
	table := NewTable()

	// 测试添加有效路由
	_, destNet, _ := net.ParseCIDR("192.168.1.0/24")
	gateway := net.ParseIP("10.0.0.1")

	route := Route{
		Destination: destNet,
		Gateway:     gateway,
		Interface:   "eth0",
		Metric:      1,
		Type:        RouteTypeStatic,
	}

	err := table.AddRoute(route)
	if err != nil {
		t.Errorf("AddRoute() failed: %v", err)
	}

	routes := table.GetAllRoutes()
	if len(routes) != 1 {
		t.Errorf("Expected 1 route, got %d", len(routes))
	}

	// 验证路由内容
	addedRoute := routes[0]
	if addedRoute.Destination.String() != destNet.String() {
		t.Errorf("Expected destination %s, got %s", destNet.String(), addedRoute.Destination.String())
	}
	if !addedRoute.Gateway.Equal(gateway) {
		t.Errorf("Expected gateway %s, got %s", gateway.String(), addedRoute.Gateway.String())
	}
	if addedRoute.Interface != "eth0" {
		t.Errorf("Expected interface eth0, got %s", addedRoute.Interface)
	}
	if addedRoute.Metric != 1 {
		t.Errorf("Expected metric 1, got %d", addedRoute.Metric)
	}
}

func TestRemoveRoute(t *testing.T) {
	table := NewTable()

	// 添加路由
	_, destNet, _ := net.ParseCIDR("192.168.1.0/24")
	gateway := net.ParseIP("10.0.0.1")

	route := Route{
		Destination: destNet,
		Gateway:     gateway,
		Interface:   "eth0",
		Metric:      1,
		Type:        RouteTypeStatic,
	}

	_ = table.AddRoute(route)

	// 删除路由
	err := table.RemoveRoute(destNet, gateway, "eth0")
	if err != nil {
		t.Errorf("RemoveRoute() failed: %v", err)
	}

	routes := table.GetAllRoutes()
	if len(routes) != 0 {
		t.Errorf("Expected 0 routes after deletion, got %d", len(routes))
	}

	// 尝试删除不存在的路由
	err = table.RemoveRoute(destNet, gateway, "eth0")
	if err == nil {
		t.Error("Expected error when deleting non-existent route")
	}
}

func TestLookupRoute(t *testing.T) {
	table := NewTable()

	// 添加测试路由
	routes := []struct {
		dest, gateway string
		iface         string
		metric        int
	}{
		{"192.168.1.0/24", "10.0.0.1", "eth0", 1},
		{"192.168.2.0/24", "10.0.0.2", "eth1", 2},
		{"0.0.0.0/0", "10.0.0.1", "eth0", 10}, // 默认路由
	}

	for _, r := range routes {
		_, destNet, _ := net.ParseCIDR(r.dest)
		gateway := net.ParseIP(r.gateway)

		route := Route{
			Destination: destNet,
			Gateway:     gateway,
			Interface:   r.iface,
			Metric:      r.metric,
			Type:        RouteTypeStatic,
		}
		_ = table.AddRoute(route)
	}

	// 测试路由查找
	testCases := []struct {
		ip           string
		expectedDest string
		shouldFind   bool
	}{
		{"192.168.1.100", "192.168.1.0/24", true}, // 匹配第一个网络
		{"192.168.2.50", "192.168.2.0/24", true},  // 匹配第二个网络
		{"8.8.8.8", "0.0.0.0/0", true},            // 匹配默认路由
		{"192.168.1.1", "192.168.1.0/24", true},   // 匹配第一个网络
	}

	for _, tc := range testCases {
		ip := net.ParseIP(tc.ip)
		route, err := table.LookupRoute(ip)

		if tc.shouldFind {
			if err != nil {
				t.Errorf("LookupRoute(%s) failed: %v", tc.ip, err)
				continue
			}
			if route.Destination.String() != tc.expectedDest {
				t.Errorf("LookupRoute(%s) expected destination %s, got %s",
					tc.ip, tc.expectedDest, route.Destination.String())
			}
		} else {
			if err == nil {
				t.Errorf("LookupRoute(%s) expected to fail but found route", tc.ip)
			}
		}
	}
}

func TestRouteMetricComparison(t *testing.T) {
	table := NewTable()

	// 添加两个到同一目标的路由，不同度量值
	_, destNet, _ := net.ParseCIDR("192.168.1.0/24")

	route1 := Route{
		Destination: destNet,
		Gateway:     net.ParseIP("10.0.0.1"),
		Interface:   "eth0",
		Metric:      5,
		Type:        RouteTypeStatic,
	}

	route2 := Route{
		Destination: destNet,
		Gateway:     net.ParseIP("10.0.0.2"),
		Interface:   "eth1",
		Metric:      1, // 更低的度量值，应该被优选
		Type:        RouteTypeStatic,
	}

	_ = table.AddRoute(route1)
	_ = table.AddRoute(route2)

	// 查找路由，应该返回度量值更低的路由
	ip := net.ParseIP("192.168.1.100")
	route, err := table.LookupRoute(ip)
	if err != nil {
		t.Errorf("LookupRoute() failed: %v", err)
	}

	if route.Metric != 1 {
		t.Errorf("Expected route with metric 1, got metric %d", route.Metric)
	}
	if route.Interface != "eth1" {
		t.Errorf("Expected interface eth1, got %s", route.Interface)
	}
}

func TestGetAllRoutes(t *testing.T) {
	table := NewTable()

	// 添加多个路由
	routeConfigs := []struct {
		dest, gateway string
		iface         string
		metric        int
	}{
		{"192.168.1.0/24", "10.0.0.1", "eth0", 1},
		{"192.168.2.0/24", "10.0.0.2", "eth1", 2},
		{"10.0.0.0/8", "192.168.1.1", "eth2", 3},
	}

	for _, config := range routeConfigs {
		_, destNet, _ := net.ParseCIDR(config.dest)
		gateway := net.ParseIP(config.gateway)

		route := Route{
			Destination: destNet,
			Gateway:     gateway,
			Interface:   config.iface,
			Metric:      config.metric,
			Type:        RouteTypeStatic,
		}
		_ = table.AddRoute(route)
	}

	routes := table.GetAllRoutes()
	if len(routes) != len(routeConfigs) {
		t.Errorf("Expected %d routes, got %d", len(routeConfigs), len(routes))
	}

	// 验证所有路由都存在
	for _, config := range routeConfigs {
		found := false
		for _, route := range routes {
			if route.Destination.String() == config.dest &&
				route.Gateway.String() == config.gateway &&
				route.Interface == config.iface &&
				route.Metric == config.metric {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Route %s via %s not found in GetAllRoutes()", config.dest, config.gateway)
		}
	}
}
