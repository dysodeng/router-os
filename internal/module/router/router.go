package router

import (
	"fmt"
	"sync"

	"router-os/internal/module/interfaces"
	"router-os/internal/module/packet"
	"router-os/internal/module/routing"
)

// Router 路由器主结构
type Router struct {
	routingTable     routing.TableInterface
	interfaceManager *interfaces.Manager
	packetProcessor  *packet.Processor
	running          bool
	mu               sync.RWMutex
	config           *RouterConfig
}

// NewRouter 创建新的路由器实例
func NewRouter() (*Router, error) {
	return NewRouterWithConfig(DefaultOptimizedRouterConfig())
}

// NewRouterWithConfig 使用配置创建新的路由器实例
func NewRouterWithConfig(config *RouterConfig) (*Router, error) {
	var routingTable routing.TableInterface

	// 根据配置选择路由表类型
	switch config.RoutingTableType {
	case routing.RouteTableTypeBasic:
		routingTable = routing.NewTable()
	case routing.RouteTableTypeOptimized:
		routingConfig := config.ToRoutingConfig()
		routingTable = routing.NewOptimizedTable(routingConfig)
	default:
		routingTable = routing.NewTable()
	}

	interfaceManager := interfaces.NewManager()
	packetProcessor := packet.NewProcessor(routingTable, interfaceManager)

	return &Router{
		routingTable:     routingTable,
		interfaceManager: interfaceManager,
		packetProcessor:  packetProcessor,
		running:          false,
		config:           config,
	}, nil
}

// Start 启动路由器
func (r *Router) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("路由器已经在运行")
	}

	// 启动接口管理器
	if err := r.interfaceManager.Start(); err != nil {
		return fmt.Errorf("启动接口管理器失败: %v", err)
	}

	// 启动数据包处理器
	if err := r.packetProcessor.Start(); err != nil {
		return fmt.Errorf("启动数据包处理器失败: %v", err)
	}

	r.running = true
	return nil
}

// Stop 停止路由器
func (r *Router) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return
	}

	r.packetProcessor.Stop()
	r.interfaceManager.Stop()
	r.running = false
}

// IsRunning 检查路由器是否在运行
func (r *Router) IsRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

// GetRoutingTable 获取路由表
func (r *Router) GetRoutingTable() routing.TableInterface {
	return r.routingTable
}

// GetInterfaceManager 获取接口管理器
func (r *Router) GetInterfaceManager() *interfaces.Manager {
	return r.interfaceManager
}

// GetPacketProcessor 获取数据包处理器
func (r *Router) GetPacketProcessor() *packet.Processor {
	return r.packetProcessor
}
