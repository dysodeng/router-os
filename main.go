package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"router-os/internal/cli"
	"router-os/internal/config"
	"router-os/internal/logging"
	"router-os/internal/monitoring"
	"router-os/internal/protocols"
	"router-os/internal/router"
)

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

	logger.Info("Router OS 已启动")
	fmt.Println("Router OS 已启动")

	// 创建并启动CLI
	cliInterface := cli.NewCLI(r, configManager, staticManager, ripManager)
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

	// 停止路由器
	r.Stop()

	logger.Info("Router OS 已关闭")
	fmt.Println("Router OS 已关闭")
}
