package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"router-os/internal/cli"
	"router-os/internal/config"
	"router-os/internal/logging"
	"router-os/internal/monitoring"
	"router-os/internal/protocols"
	"router-os/internal/router"
)

func parseSystemID(systemIDStr string) []byte {
	// 解析系统ID字符串为字节数组
	// 格式: "1234.5678.9012" -> [0x12, 0x34, 0x56, 0x78, 0x90, 0x12]
	parts := strings.Split(systemIDStr, ".")
	if len(parts) != 3 {
		return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01} // 默认系统ID
	}

	systemID := make([]byte, 6)
	for i, part := range parts {
		if val, err := strconv.ParseUint(part, 16, 16); err == nil {
			systemID[i*2] = byte(val >> 8)
			systemID[i*2+1] = byte(val & 0xFF)
		}
	}

	return systemID
}

func main() {
	fmt.Println("Router OS 启动中...")

	// 初始化配置管理器
	configManager := config.NewConfigManager("config.json")
	if err := configManager.LoadConfig(); err != nil {
		log.Printf("加载配置失败，使用默认配置: %v", err)
	}

	cfg := configManager.GetConfig()

	// 初始化日志系统
	logger := logging.NewLogger(logging.ParseLogLevel(cfg.LogLevel), cfg.LogFile)
	defer func() {
		_ = logger.Close()
	}()

	logger.Info("Router OS 启动中...")

	// 创建路由器实例
	r, err := router.NewRouter()
	if err != nil {
		logger.Fatal("创建路由器失败: %v", err)
	}

	// 创建协议管理器
	staticManager := protocols.NewStaticRouteManager(r.GetRoutingTable())
	ripManager := protocols.NewRIPManager(r.GetRoutingTable(), r.GetInterfaceManager())

	// 创建新协议管理器（始终创建，以便CLI可以使用）
	ospfManager := protocols.NewOSPFManager(
		r.GetRoutingTable(),
		r.GetInterfaceManager(),
	)

	// 使用默认AS号65001，如果配置中有则使用配置的值
	localAS := uint16(65001)
	if cfg.BGP.LocalAS != 0 {
		localAS = uint16(cfg.BGP.LocalAS)
	}
	bgpManager := protocols.NewBGPManager(
		localAS,
		r.GetRoutingTable(),
		r.GetInterfaceManager(),
	)

	// 使用默认系统ID，如果配置中有则使用配置的值
	systemID := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	if cfg.ISIS.SystemID != "" {
		systemID = parseSystemID(cfg.ISIS.SystemID)
	}
	isisManager := protocols.NewISISManager(
		systemID,
		r.GetRoutingTable(),
		logger,
	)

	// 创建监控器
	monitor := monitoring.NewMonitor(r.GetRoutingTable(), r.GetInterfaceManager())

	// 启动路由器
	if err := r.Start(); err != nil {
		logger.Fatal("启动路由器失败: %v", err)
	}

	// 启动监控
	monitor.Start()
	defer monitor.Stop()

	// 加载静态路由配置
	for _, routeConfig := range cfg.StaticRoutes {
		if err := staticManager.AddStaticRoute(
			routeConfig.Destination,
			routeConfig.Gateway,
			routeConfig.Interface,
			routeConfig.Metric,
		); err != nil {
			logger.Error("添加静态路由失败: %v", err)
		}
	}

	// 启动RIP协议（如果配置启用）
	if cfg.RIP.Enabled {
		if err := ripManager.Start(); err != nil {
			logger.Error("启动RIP协议失败: %v", err)
		} else {
			logger.Info("RIP协议已启动")
		}
	}

	// 启动新协议（根据配置决定是否自动启动）
	if cfg.OSPF.Enabled {
		if err := ospfManager.Start(); err != nil {
			logger.Error("Failed to start OSPF manager", "error", err)
		} else {
			logger.Info("OSPF manager started successfully")
		}
	}

	if cfg.BGP.Enabled {
		if err := bgpManager.Start(); err != nil {
			logger.Error("Failed to start BGP manager", "error", err)
		} else {
			logger.Info("BGP manager started successfully")
		}
	}

	if cfg.ISIS.Enabled {
		if err := isisManager.Start(); err != nil {
			logger.Error("Failed to start IS-IS manager", "error", err)
		} else {
			logger.Info("IS-IS manager started successfully")
		}
	}

	logger.Info("Router OS 已启动")
	fmt.Println("Router OS 已启动")

	// 创建并启动CLI
	cliInterface := cli.NewCLI(r, configManager, staticManager, ripManager, ospfManager, bgpManager, isisManager)
	go cliInterface.Start()

	// 等待中断信号或CLI退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		// 收到系统信号
	case <-cliInterface.GetExitChan():
		// CLI主动退出
	}

	logger.Info("正在关闭 Router OS...")
	fmt.Println("正在关闭 Router OS...")

	// 停止CLI
	cliInterface.Stop()

	// 停止RIP协议
	if cfg.RIP.Enabled {
		ripManager.Stop()
		logger.Info("RIP协议已停止")
	}

	// 停止新协议
	if ospfManager != nil {
		ospfManager.Stop()
		logger.Info("OSPF manager stopped")
	}

	if bgpManager != nil {
		bgpManager.Stop()
		logger.Info("BGP manager stopped")
	}

	if isisManager != nil {
		isisManager.Stop()
		logger.Info("IS-IS manager stopped")
	}

	// 停止路由器
	r.Stop()

	logger.Info("Router OS 已关闭")
	fmt.Println("Router OS 已关闭")
}
