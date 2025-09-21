package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"router-os/internal/config"
	"router-os/internal/packet"
	"router-os/internal/protocols"
	"router-os/internal/router"

	"github.com/chzyer/readline"
)

// CLI 命令行接口
type CLI struct {
	router        *router.Router
	configManager *config.ConfigManager
	staticManager *protocols.StaticRouteManager
	ripManager    *protocols.RIPManager
	ospfManager   *protocols.OSPFManager
	bgpManager    *protocols.BGPManager
	isisManager   *protocols.ISISManager
	running       bool
	exitChan      chan bool
	rl            *readline.Instance
	historyFile   string
}

// NewCLI 创建CLI实例
func NewCLI(
	r *router.Router,
	cm *config.ConfigManager,
	sm *protocols.StaticRouteManager,
	rm *protocols.RIPManager,
	om *protocols.OSPFManager,
	bm *protocols.BGPManager,
	im *protocols.ISISManager,
) *CLI {
	// 获取用户主目录
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}

	historyFile := filepath.Join(homeDir, ".router-os_history")

	return &CLI{
		router:        r,
		configManager: cm,
		staticManager: sm,
		ripManager:    rm,
		ospfManager:   om,
		bgpManager:    bm,
		isisManager:   im,
		running:       false,
		exitChan:      make(chan bool, 1),
		historyFile:   historyFile,
	}
}

// handlePacketCommand 处理packet命令
func (cli *CLI) handlePacketCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: packet <send|test|stats|reset>")
		return
	}

	switch args[0] {
	case "send":
		cli.handlePacketSend(args[1:])
	case "test":
		cli.handlePacketTest(args[1:])
	case "stats":
		cli.handlePacketStats()
	case "reset":
		cli.handlePacketReset()
	default:
		fmt.Printf("未知的packet子命令: %s\n", args[0])
		fmt.Println("可用子命令: send, test, stats, reset")
	}
}

// handlePacketSend 处理数据包发送
func (cli *CLI) handlePacketSend(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: packet send <源IP> <目标IP> [数据]")
		return
	}

	srcIP := args[0]
	dstIP := args[1]
	data := "Hello, Router!"
	if len(args) > 2 {
		data = strings.Join(args[2:], " ")
	}

	// 获取数据包处理器
	processor := cli.router.GetPacketProcessor()
	if processor == nil {
		fmt.Println("错误: 数据包处理器未初始化")
		return
	}

	// 创建数据包
	srcIPAddr := net.ParseIP(srcIP)
	dstIPAddr := net.ParseIP(dstIP)
	if srcIPAddr == nil || dstIPAddr == nil {
		fmt.Println("错误: 无效的IP地址格式")
		return
	}

	pkt := processor.CreatePacket(packet.PacketTypeIPv4, srcIPAddr, dstIPAddr, []byte(data), "")

	fmt.Printf("创建数据包:\n")
	fmt.Printf("  源IP: %s\n", pkt.Source.String())
	fmt.Printf("  目标IP: %s\n", pkt.Destination.String())
	fmt.Printf("  数据: %s\n", string(pkt.Data))
	fmt.Printf("  TTL: %d\n", pkt.TTL)

	// 处理数据包
	fmt.Println("\n开始处理数据包...")
	_ = processor.ProcessPacket(pkt)

	fmt.Println("数据包处理完成")
}

// handlePacketTest 处理路由测试
func (cli *CLI) handlePacketTest(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: packet test <源IP> <目标IP>")
		return
	}

	srcIP := args[0]
	dstIP := args[1]

	fmt.Printf("测试从 %s 到 %s 的路由路径:\n", srcIP, dstIP)

	// 查找路由
	routingTable := cli.router.GetRoutingTable()
	route, _ := routingTable.LookupRoute(net.ParseIP(dstIP))

	if route == nil {
		fmt.Printf("❌ 未找到到 %s 的路由\n", dstIP)
		return
	}

	fmt.Printf("✅ 找到路由:\n")
	fmt.Printf("  目标网络: %s\n", route.Destination)
	fmt.Printf("  网关: %s\n", route.Gateway)
	fmt.Printf("  接口: %s\n", route.Interface)
	fmt.Printf("  度量: %d\n", route.Metric)

	var routeType string
	switch route.Type {
	case 0: // DirectRoute
		routeType = "直连"
	case 1: // StaticRoute
		routeType = "静态"
	case 2: // RIPRoute
		routeType = "RIP"
	default:
		routeType = "未知"
	}
	fmt.Printf("  类型: %s\n", routeType)

	// 检查接口状态
	interfaceManager := cli.router.GetInterfaceManager()
	if interfaceManager != nil {
		interfaces := interfaceManager.GetAllInterfaces()
		for _, iface := range interfaces {
			if iface.Name == route.Interface {
				var status string
				switch iface.Status {
				case 0: // Up
					status = "启用"
				case 1: // Down
					status = "禁用"
				case 2: // Unknown
					status = "未知"
				default:
					status = "未知"
				}
				fmt.Printf("  接口状态: %s\n", status)
				break
			}
		}
	}
}

// handlePacketStats 显示数据包统计
func (cli *CLI) handlePacketStats() {
	processor := cli.router.GetPacketProcessor()
	if processor == nil {
		fmt.Println("错误: 数据包处理器未初始化")
		return
	}

	received, processed, forwarded, dropped := processor.GetStats()
	fmt.Println("数据包统计信息:")
	fmt.Printf("  接收数据包: %d\n", received)
	fmt.Printf("  处理数据包: %d\n", processed)
	fmt.Printf("  转发数据包: %d\n", forwarded)
	fmt.Printf("  丢弃数据包: %d\n", dropped)
}

// handlePacketReset 重置统计信息
func (cli *CLI) handlePacketReset() {
	processor := cli.router.GetPacketProcessor()
	if processor == nil {
		fmt.Println("错误: 数据包处理器未初始化")
		return
	}

	processor.ResetStats()
	fmt.Println("数据包统计信息已重置")
}

// Start 启动CLI
func (cli *CLI) Start() {
	cli.running = true
	fmt.Println("Router OS CLI 已启动")
	fmt.Println("输入 'help' 查看可用命令")
	fmt.Println("使用上下方向键浏览命令历史，Tab键自动补全")

	// 创建自动补全器
	completer := cli.createCompleter()

	// 配置readline
	cfg := &readline.Config{
		Prompt:          "router-os> ",
		HistoryFile:     cli.historyFile,
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	}

	var err error
	cli.rl, err = readline.NewEx(cfg)
	if err != nil {
		fmt.Printf("初始化CLI失败: %v\n", err)
		return
	}
	defer func() {
		_ = cli.rl.Close()
	}()

	for cli.running {
		line, err := cli.rl.Readline()
		if err != nil {
			if errors.Is(err, readline.ErrInterrupt) {
				continue
			} else if err == io.EOF {
				break
			}
			fmt.Printf("读取输入失败: %v\n", err)
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cli.processCommand(line)
	}
}

// Stop 停止CLI
func (cli *CLI) Stop() {
	cli.running = false
	select {
	case cli.exitChan <- true:
	default:
	}
}

// GetExitChan 获取退出信号channel
func (cli *CLI) GetExitChan() <-chan bool {
	return cli.exitChan
}

// processCommand 处理命令
func (cli *CLI) processCommand(line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	command := parts[0]
	args := parts[1:]

	switch command {
	case "help":
		cli.showHelp()
	case "show":
		cli.handleShowCommand(args)
	case "config":
		cli.handleConfigCommand(args)
	case "route":
		cli.handleRouteCommand(args)
	case "interface":
		cli.handleInterfaceCommand(args)
	case "rip":
		cli.handleRIPCommand(args)
	case "ospf":
		cli.handleOSPFCommand(args)
	case "bgp":
		cli.handleBGPCommand(args)
	case "isis":
		cli.handleISISCommand(args)
	case "packet":
		cli.handlePacketCommand(args)
	case "save":
		cli.handleSaveCommand()
	case "reload":
		cli.handleReloadCommand()
	case "exit", "quit":
		cli.Stop()
	default:
		fmt.Printf("未知命令: %s\n", command)
		fmt.Println("输入 'help' 查看可用命令")
	}
}

// showHelp 显示帮助信息
func (cli *CLI) showHelp() {
	fmt.Println("可用命令:")
	fmt.Println("  help                    - 显示帮助信息")
	fmt.Println("  show routes             - 显示路由表")
	fmt.Println("  show interfaces         - 显示接口信息")
	fmt.Println("  show config             - 显示配置")
	fmt.Println("  show stats              - 显示统计信息")
	fmt.Println("  route add <dest> <gw> <if> <metric> - 添加静态路由")
	fmt.Println("  route del <dest> <gw> <if>          - 删除静态路由")
	fmt.Println("  interface up <name>     - 启用接口")
	fmt.Println("  interface down <name>   - 禁用接口")
	fmt.Println("  rip enable              - 启用RIP协议")
	fmt.Println("  rip disable             - 禁用RIP协议")
	fmt.Println("  rip show neighbors      - 显示RIP邻居")
	fmt.Println("  ospf start              - 启动OSPF协议")
	fmt.Println("  ospf stop               - 停止OSPF协议")
	fmt.Println("  ospf status             - 显示OSPF状态")
	fmt.Println("  bgp start               - 启动BGP协议")
	fmt.Println("  bgp stop                - 停止BGP协议")
	fmt.Println("  bgp status              - 显示BGP状态")
	fmt.Println("  isis start              - 启动IS-IS协议")
	fmt.Println("  isis stop               - 停止IS-IS协议")
	fmt.Println("  isis status             - 显示IS-IS状态")
	fmt.Println("  packet send <src> <dst> [data]      - 模拟发送数据包")
	fmt.Println("  packet test <src> <dst>             - 测试路由路径")
	fmt.Println("  packet stats                        - 显示数据包统计")
	fmt.Println("  packet reset                        - 重置统计信息")
	fmt.Println("  config hostname <name>  - 设置主机名")
	fmt.Println("  save                    - 保存配置")
	fmt.Println("  reload                  - 重新加载配置")
	fmt.Println("  exit/quit               - 退出CLI")
}

// handleShowCommand 处理show命令
func (cli *CLI) handleShowCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: show <routes|interfaces|config|stats>")
		return
	}

	switch args[0] {
	case "routes":
		cli.showRoutes()
	case "interfaces":
		cli.showInterfaces()
	case "config":
		cli.showConfig()
	case "stats":
		cli.showStats()
	default:
		fmt.Printf("未知的show子命令: %s\n", args[0])
	}
}

// showRoutes 显示路由表
func (cli *CLI) showRoutes() {
	routes := cli.router.GetRoutingTable().GetAllRoutes()

	fmt.Println("路由表:")
	fmt.Printf("%-18s %-15s %-10s %-6s %-8s\n", "目标网络", "网关", "接口", "度量", "类型")
	fmt.Println(strings.Repeat("-", 70))

	for _, route := range routes {
		var routeType string
		switch route.Type {
		case 0: // RouteTypeStatic
			routeType = "静态"
		case 1: // RouteTypeDynamic
			routeType = "动态"
		case 2: // RouteTypeConnected
			routeType = "连接"
		case 3: // RouteTypeDefault
			routeType = "默认"
		}

		fmt.Printf("%-18s %-15s %-10s %-6d %-8s\n",
			route.Destination.String(),
			route.Gateway.String(),
			route.Interface,
			route.Metric,
			routeType)
	}
}

// showInterfaces 显示接口信息
func (cli *CLI) showInterfaces() {
	interfaces := cli.router.GetInterfaceManager().GetAllInterfaces()

	fmt.Println("接口信息:")
	fmt.Printf("%-10s %-15s %-15s %-6s %-8s\n", "接口", "IP地址", "子网掩码", "MTU", "状态")
	fmt.Println(strings.Repeat("-", 70))

	for _, iface := range interfaces {
		var status string
		switch iface.Status {
		case 0: // InterfaceStatusDown
			status = "关闭"
		case 1: // InterfaceStatusUp
			status = "启用"
		case 2: // InterfaceStatusTesting
			status = "测试"
		}

		ipAddr := "未配置"
		netmask := "未配置"
		if iface.IPAddress != nil {
			ipAddr = iface.IPAddress.String()
		}
		if iface.Netmask != nil {
			netmask = fmt.Sprintf("%d.%d.%d.%d", iface.Netmask[0], iface.Netmask[1], iface.Netmask[2], iface.Netmask[3])
		}

		fmt.Printf("%-10s %-15s %-15s %-6d %-8s\n",
			iface.Name, ipAddr, netmask, iface.MTU, status)
	}
}

// showConfig 显示配置
func (cli *CLI) showConfig() {
	config := cli.configManager.GetConfig()

	fmt.Printf("主机名: %s\n", config.Hostname)
	fmt.Printf("日志级别: %s\n", config.LogLevel)
	fmt.Printf("日志文件: %s\n", config.LogFile)
	fmt.Printf("RIP协议: %v\n", config.RIP.Enabled)
}

// showStats 显示统计信息
func (cli *CLI) showStats() {
	interfaces := cli.router.GetInterfaceManager().GetActiveInterfaces()

	fmt.Println("数据包统计:")
	if len(interfaces) > 0 {
		fmt.Printf("接收: %d\n", interfaces[0].RxPackets)
		fmt.Printf("发送: %d\n", interfaces[0].TxPackets)
		fmt.Printf("接收字节: %d\n", interfaces[0].RxBytes)
		fmt.Printf("发送字节: %d\n", interfaces[0].TxBytes)
		fmt.Printf("错误: %d\n", interfaces[0].Errors)
	} else {
		fmt.Println("没有活跃的接口")
	}
}

// handleRouteCommand 处理route命令
func (cli *CLI) handleRouteCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: route <add|del> ...")
		return
	}

	switch args[0] {
	case "add":
		if len(args) != 5 {
			fmt.Println("用法: route add <destination> <gateway> <interface> <metric>")
			return
		}

		metric, err := strconv.Atoi(args[4])
		if err != nil {
			fmt.Printf("无效的度量值: %s\n", args[4])
			return
		}

		if err := cli.staticManager.AddStaticRoute(args[1], args[2], args[3], metric); err != nil {
			fmt.Printf("添加路由失败: %v\n", err)
		} else {
			fmt.Println("路由添加成功")
		}

	case "del":
		if len(args) != 4 {
			fmt.Println("用法: route del <destination> <gateway> <interface>")
			return
		}

		if err := cli.staticManager.RemoveStaticRoute(args[1], args[2], args[3]); err != nil {
			fmt.Printf("删除路由失败: %v\n", err)
		} else {
			fmt.Println("路由删除成功")
		}

	default:
		fmt.Printf("未知的route子命令: %s\n", args[0])
	}
}

// handleInterfaceCommand 处理interface命令
func (cli *CLI) handleInterfaceCommand(args []string) {
	if len(args) != 2 {
		fmt.Println("用法: interface <up|down> <interface_name>")
		return
	}

	interfaceName := args[1]

	switch args[0] {
	case "up":
		if err := cli.router.GetInterfaceManager().SetInterfaceStatus(interfaceName, 1); err != nil {
			fmt.Printf("启用接口失败: %v\n", err)
		} else {
			fmt.Printf("接口 %s 已启用\n", interfaceName)
		}

	case "down":
		if err := cli.router.GetInterfaceManager().SetInterfaceStatus(interfaceName, 0); err != nil {
			fmt.Printf("禁用接口失败: %v\n", err)
		} else {
			fmt.Printf("接口 %s 已禁用\n", interfaceName)
		}

	default:
		fmt.Printf("未知的interface子命令: %s\n", args[0])
	}
}

// handleRIPCommand 处理RIP命令
func (cli *CLI) handleRIPCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: rip <enable|disable|show> ...")
		return
	}

	switch args[0] {
	case "enable":
		if err := cli.ripManager.Start(); err != nil {
			fmt.Printf("启用RIP失败: %v\n", err)
		} else {
			fmt.Println("RIP协议已启用")
		}

	case "disable":
		cli.ripManager.Stop()
		fmt.Println("RIP协议已禁用")

	case "show":
		if len(args) > 1 && args[1] == "neighbors" {
			neighbors := cli.ripManager.GetNeighbors()
			fmt.Println("RIP邻居:")
			for neighbor, lastSeen := range neighbors {
				fmt.Printf("  %s (最后更新: %s)\n", neighbor, lastSeen.In(time.Local).Format("2006-01-02 15:04:05 CST"))
			}
		}

	default:
		fmt.Printf("未知的rip子命令: %s\n", args[0])
	}
}

// handleConfigCommand 处理config命令
func (cli *CLI) handleConfigCommand(args []string) {
	if len(args) < 2 {
		fmt.Println("用法: config <hostname> <value>")
		return
	}

	switch args[0] {
	case "hostname":
		cli.configManager.SetHostname(args[1])
		fmt.Printf("主机名已设置为: %s\n", args[1])
	default:
		fmt.Printf("未知的config子命令: %s\n", args[0])
	}
}

// handleSaveCommand 处理save命令
func (cli *CLI) handleSaveCommand() {
	if err := cli.configManager.SaveConfig(); err != nil {
		fmt.Printf("保存配置失败: %v\n", err)
	} else {
		fmt.Println("配置已保存")
	}
}

// handleReloadCommand 处理reload命令
func (cli *CLI) handleReloadCommand() {
	if err := cli.configManager.LoadConfig(); err != nil {
		fmt.Printf("重新加载配置失败: %v\n", err)
	} else {
		fmt.Println("配置已重新加载")
	}
}

// createCompleter 创建自动补全器
func (cli *CLI) createCompleter() readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("help"),
		readline.PcItem("show",
			readline.PcItem("routes"),
			readline.PcItem("interfaces"),
			readline.PcItem("config"),
			readline.PcItem("stats"),
		),
		readline.PcItem("route",
			readline.PcItem("add"),
			readline.PcItem("del"),
		),
		readline.PcItem("interface",
			readline.PcItem("up"),
			readline.PcItem("down"),
		),
		readline.PcItem("rip",
			readline.PcItem("enable"),
			readline.PcItem("disable"),
			readline.PcItem("show",
				readline.PcItem("neighbors"),
			),
		),
		readline.PcItem("ospf",
			readline.PcItem("start"),
			readline.PcItem("stop"),
			readline.PcItem("status"),
		),
		readline.PcItem("bgp",
			readline.PcItem("start"),
			readline.PcItem("stop"),
			readline.PcItem("status"),
		),
		readline.PcItem("isis",
			readline.PcItem("start"),
			readline.PcItem("stop"),
			readline.PcItem("status"),
		),
		readline.PcItem("packet",
			readline.PcItem("send"),
			readline.PcItem("test"),
			readline.PcItem("stats"),
			readline.PcItem("reset"),
		),
		readline.PcItem("config",
			readline.PcItem("hostname"),
		),
		readline.PcItem("save"),
		readline.PcItem("reload"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}

// handleOSPFCommand 处理OSPF命令
func (cli *CLI) handleOSPFCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: ospf <start|stop|status>")
		return
	}

	switch args[0] {
	case "start":
		if cli.ospfManager != nil {
			if err := cli.ospfManager.Start(); err != nil {
				fmt.Printf("启动OSPF失败: %v\n", err)
			} else {
				fmt.Println("OSPF已启动")
			}
		} else {
			fmt.Println("OSPF管理器未初始化")
		}
	case "stop":
		if cli.ospfManager != nil {
			cli.ospfManager.Stop()
			fmt.Println("OSPF已停止")
		} else {
			fmt.Println("OSPF管理器未初始化")
		}
	case "status":
		if cli.ospfManager != nil {
			fmt.Println("OSPF状态: 运行中")
		} else {
			fmt.Println("OSPF状态: 未启动")
		}
	default:
		fmt.Printf("未知的OSPF命令: %s\n", args[0])
		fmt.Println("可用命令: start, stop, status")
	}
}

// handleBGPCommand 处理BGP命令
func (cli *CLI) handleBGPCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: bgp <start|stop|status>")
		return
	}

	switch args[0] {
	case "start":
		if cli.bgpManager != nil {
			if err := cli.bgpManager.Start(); err != nil {
				fmt.Printf("启动BGP失败: %v\n", err)
			} else {
				fmt.Println("BGP已启动")
			}
		} else {
			fmt.Println("BGP管理器未初始化")
		}
	case "stop":
		if cli.bgpManager != nil {
			cli.bgpManager.Stop()
			fmt.Println("BGP已停止")
		} else {
			fmt.Println("BGP管理器未初始化")
		}
	case "status":
		if cli.bgpManager != nil {
			fmt.Println("BGP状态: 运行中")
		} else {
			fmt.Println("BGP状态: 未启动")
		}
	default:
		fmt.Printf("未知的BGP命令: %s\n", args[0])
		fmt.Println("可用命令: start, stop, status")
	}
}

// handleISISCommand 处理IS-IS命令
func (cli *CLI) handleISISCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("用法: isis <start|stop|status>")
		return
	}

	switch args[0] {
	case "start":
		if cli.isisManager != nil {
			if err := cli.isisManager.Start(); err != nil {
				fmt.Printf("启动IS-IS失败: %v\n", err)
			} else {
				fmt.Println("IS-IS已启动")
			}
		} else {
			fmt.Println("IS-IS管理器未初始化")
		}
	case "stop":
		if cli.isisManager != nil {
			_ = cli.isisManager.Stop()
			fmt.Println("IS-IS已停止")
		} else {
			fmt.Println("IS-IS管理器未初始化")
		}
	case "status":
		if cli.isisManager != nil {
			fmt.Println("IS-IS状态: 运行中")
		} else {
			fmt.Println("IS-IS状态: 未启动")
		}
	default:
		fmt.Printf("未知的IS-IS命令: %s\n", args[0])
		fmt.Println("可用命令: start, stop, status")
	}
}
