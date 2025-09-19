package protocols

import (
	"testing"

	"router-os/internal/routing"
)

// TestStaticRouteManagerBasic 测试静态路由管理器基本功能
func TestStaticRouteManagerBasic(t *testing.T) {
	// 创建路由表
	table := routing.NewTable()

	// 创建静态路由管理器
	manager := NewStaticRouteManager(table)

	// 测试添加路由
	err := manager.AddStaticRoute("192.168.1.0/24", "192.168.0.1", "eth0", 1)
	if err != nil {
		t.Errorf("添加静态路由失败: %v", err)
	}

	// 验证路由是否添加成功
	routes := table.GetAllRoutes()
	if len(routes) != 1 {
		t.Errorf("期望1条路由，实际得到%d条", len(routes))
	}

	// 验证路由内容
	route := routes[0]
	if route.Destination.String() != "192.168.1.0/24" {
		t.Errorf("期望目标网络为192.168.1.0/24，实际为%s", route.Destination.String())
	}

	if route.Gateway.String() != "192.168.0.1" {
		t.Errorf("期望网关为192.168.0.1，实际为%s", route.Gateway.String())
	}

	if route.Interface != "eth0" {
		t.Errorf("期望接口为eth0，实际为%s", route.Interface)
	}

	if route.Metric != 1 {
		t.Errorf("期望度量值为1，实际为%d", route.Metric)
	}

	if route.Type != routing.RouteTypeStatic {
		t.Errorf("期望路由类型为静态，实际为%v", route.Type)
	}

	// 测试删除路由
	err = manager.RemoveStaticRoute("192.168.1.0/24", "192.168.0.1", "eth0")
	if err != nil {
		t.Errorf("删除静态路由失败: %v", err)
	}

	// 验证路由是否删除成功
	routes = table.GetAllRoutes()
	if len(routes) != 0 {
		t.Errorf("期望0条路由，实际得到%d条", len(routes))
	}
}

// TestStaticRouteManagerMultiple 测试多条静态路由
func TestStaticRouteManagerMultiple(t *testing.T) {
	table := routing.NewTable()
	manager := NewStaticRouteManager(table)

	// 添加多条静态路由
	routes := []struct {
		dest, gw, iface string
		metric          int
	}{
		{"192.168.1.0/24", "192.168.0.1", "eth0", 1},
		{"10.0.0.0/8", "192.168.0.1", "eth0", 2},
		{"172.16.0.0/12", "192.168.0.2", "eth1", 1},
	}

	for _, route := range routes {
		err := manager.AddStaticRoute(route.dest, route.gw, route.iface, route.metric)
		if err != nil {
			t.Errorf("添加静态路由 %s 失败: %v", route.dest, err)
		}
	}

	// 验证所有路由都添加成功
	allRoutes := table.GetAllRoutes()
	if len(allRoutes) != len(routes) {
		t.Errorf("期望 %d 条路由，实际得到 %d 条", len(routes), len(allRoutes))
	}

	// 删除所有路由
	for _, route := range routes {
		err := manager.RemoveStaticRoute(route.dest, route.gw, route.iface)
		if err != nil {
			t.Errorf("删除静态路由 %s 失败: %v", route.dest, err)
		}
	}

	// 验证所有路由都删除成功
	allRoutes = table.GetAllRoutes()
	if len(allRoutes) != 0 {
		t.Errorf("期望 0 条路由，实际得到 %d 条", len(allRoutes))
	}
}

// TestStaticRouteManagerErrors 测试错误情况
func TestStaticRouteManagerErrors(t *testing.T) {
	table := routing.NewTable()
	manager := NewStaticRouteManager(table)

	// 测试添加无效的路由
	err := manager.AddStaticRoute("invalid-network", "192.168.0.1", "eth0", 1)
	if err == nil {
		t.Error("期望添加无效网络时返回错误")
	}

	// 测试添加无效的网关
	err = manager.AddStaticRoute("192.168.1.0/24", "invalid-gateway", "eth0", 1)
	if err == nil {
		t.Error("期望添加无效网关时返回错误")
	}

	// 测试删除不存在的路由
	err = manager.RemoveStaticRoute("192.168.99.0/24", "192.168.0.1", "eth0")
	if err == nil {
		t.Error("期望删除不存在的路由时返回错误")
	}
}

// BenchmarkStaticRouteOperations 静态路由操作性能基准测试
func BenchmarkStaticRouteOperations(b *testing.B) {
	table := routing.NewTable()
	manager := NewStaticRouteManager(table)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 添加路由
		_ = manager.AddStaticRoute("192.168.1.0/24", "192.168.0.1", "eth0", 1)

		// 删除路由
		_ = manager.RemoveStaticRoute("192.168.1.0/24", "192.168.0.1", "eth0")
	}
}
