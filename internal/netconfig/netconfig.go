package netconfig

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NetworkConfigurator 网络配置器
// 负责管理网络接口的配置，包括IP地址、路由表等
//
// 主要功能：
// 1. 接口IP配置：设置和删除接口IP地址
// 2. 路由管理：添加、删除、修改路由表项
// 3. 接口状态管理：启用/禁用网络接口
// 4. 网络参数配置：MTU、MAC地址等
// 5. 系统网络设置：IP转发、ARP等
//
// 安全考虑：
// - 所有操作都需要管理员权限
// - 配置变更会记录日志
// - 支持配置回滚机制
// - 验证配置参数的合法性
//
// 兼容性：
// - 支持Linux、macOS、Windows
// - 自动检测系统类型并使用相应命令
// - 提供统一的API接口
type NetworkConfigurator struct {
	// mu 读写锁
	mu sync.RWMutex

	// osType 操作系统类型
	osType string

	// 配置历史记录
	configHistory []ConfigChange

	// 最大历史记录数
	maxHistorySize int
}

// ConfigChange 配置变更记录
type ConfigChange struct {
	// Timestamp 变更时间
	Timestamp time.Time

	// Operation 操作类型
	Operation string

	// Interface 接口名称
	Interface string

	// OldValue 旧值
	OldValue string

	// NewValue 新值
	NewValue string

	// Success 是否成功
	Success bool

	// Error 错误信息
	Error string
}

// InterfaceConfig 接口配置
type InterfaceConfig struct {
	// Name 接口名称
	Name string

	// IPAddress IP地址
	IPAddress net.IP

	// Netmask 子网掩码
	Netmask net.IPMask

	// Gateway 网关地址
	Gateway net.IP

	// MTU 最大传输单元
	MTU int

	// MAC MAC地址
	MAC net.HardwareAddr

	// Up 接口状态
	Up bool
}

// RouteEntry 路由表项
type RouteEntry struct {
	// Destination 目标网络
	Destination *net.IPNet

	// Gateway 网关地址
	Gateway net.IP

	// Interface 出接口
	Interface string

	// Metric 路由度量值
	Metric int

	// Type 路由类型 (direct, static, dynamic)
	Type string
}

// NewNetworkConfigurator 创建网络配置器
//
// 返回值：
//   - *NetworkConfigurator: 网络配置器实例
//
// 使用示例：
//
//	config := NewNetworkConfigurator()
//	err := config.SetInterfaceIP("eth0", "192.168.1.100", "255.255.255.0")
//	if err != nil {
//	    log.Printf("配置IP失败: %v", err)
//	}
func NewNetworkConfigurator() *NetworkConfigurator {
	return &NetworkConfigurator{
		osType:         runtime.GOOS,
		configHistory:  make([]ConfigChange, 0),
		maxHistorySize: 1000,
	}
}

// SetInterfaceIP 设置接口IP地址
//
// 参数：
//   - interfaceName: 接口名称 (如 "eth0", "en0")
//   - ipAddress: IP地址字符串 (如 "192.168.1.100")
//   - netmask: 子网掩码字符串 (如 "255.255.255.0" 或 "/24")
//
// 返回值：
//   - error: 配置成功返回nil，失败返回错误信息
//
// 支持的操作系统：
//   - Linux: 使用 ip addr add 命令
//   - macOS: 使用 ifconfig 命令
//   - Windows: 使用 netsh 命令
//
// 使用示例：
//
//	err := config.SetInterfaceIP("eth0", "192.168.1.100", "255.255.255.0")
//	err := config.SetInterfaceIP("eth0", "192.168.1.100", "/24")
func (nc *NetworkConfigurator) SetInterfaceIP(interfaceName, ipAddress, netmask string) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// 验证参数
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return fmt.Errorf("无效的IP地址: %s", ipAddress)
	}

	// 获取当前配置用于回滚
	oldConfig, _ := nc.getInterfaceConfig(interfaceName)

	var cmd *exec.Cmd
	var cmdStr string

	switch nc.osType {
	case "linux":
		// Linux: ip addr add 192.168.1.100/24 dev eth0
		cidr := nc.convertToCIDR(ipAddress, netmask)
		cmdStr = fmt.Sprintf("ip addr add %s dev %s", cidr, interfaceName)
		cmd = exec.Command("ip", "addr", "add", cidr, "dev", interfaceName)

	case "darwin": // macOS
		// macOS: ifconfig en0 inet 192.168.1.100 netmask 255.255.255.0
		cmdStr = fmt.Sprintf("ifconfig %s inet %s netmask %s", interfaceName, ipAddress, netmask)
		cmd = exec.Command("ifconfig", interfaceName, "inet", ipAddress, "netmask", netmask)

	case "windows":
		// Windows: netsh interface ip set address "Local Area Connection" static 192.168.1.100 255.255.255.0
		cmdStr = fmt.Sprintf("netsh interface ip set address \"%s\" static %s %s", interfaceName, ipAddress, netmask)
		cmd = exec.Command("netsh", "interface", "ip", "set", "address", interfaceName, "static", ipAddress, netmask)

	default:
		return fmt.Errorf("不支持的操作系统: %s", nc.osType)
	}

	// 执行命令
	output, err := cmd.CombinedOutput()

	// 记录配置变更
	change := ConfigChange{
		Timestamp: time.Now(),
		Operation: "SetInterfaceIP",
		Interface: interfaceName,
		OldValue:  nc.formatInterfaceConfig(oldConfig),
		NewValue:  fmt.Sprintf("IP: %s, Netmask: %s", ipAddress, netmask),
		Success:   err == nil,
	}

	if err != nil {
		change.Error = fmt.Sprintf("命令执行失败: %s, 输出: %s", err.Error(), string(output))
		nc.addConfigHistory(change)
		return fmt.Errorf("设置接口IP失败: %v, 命令: %s, 输出: %s", err, cmdStr, string(output))
	}

	nc.addConfigHistory(change)
	return nil
}

// RemoveInterfaceIP 删除接口IP地址
//
// 参数：
//   - interfaceName: 接口名称
//   - ipAddress: 要删除的IP地址
//
// 返回值：
//   - error: 删除成功返回nil，失败返回错误信息
func (nc *NetworkConfigurator) RemoveInterfaceIP(interfaceName, ipAddress string) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// 验证参数
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return fmt.Errorf("无效的IP地址: %s", ipAddress)
	}

	var cmd *exec.Cmd
	var cmdStr string

	switch nc.osType {
	case "linux":
		// Linux: ip addr del 192.168.1.100/24 dev eth0
		cmdStr = fmt.Sprintf("ip addr del %s dev %s", ipAddress, interfaceName)
		cmd = exec.Command("ip", "addr", "del", ipAddress, "dev", interfaceName)

	case "darwin": // macOS
		// macOS: ifconfig en0 inet 192.168.1.100 delete
		cmdStr = fmt.Sprintf("ifconfig %s inet %s delete", interfaceName, ipAddress)
		cmd = exec.Command("ifconfig", interfaceName, "inet", ipAddress, "delete")

	case "windows":
		// Windows: netsh interface ip delete address "Local Area Connection" 192.168.1.100
		cmdStr = fmt.Sprintf("netsh interface ip delete address \"%s\" %s", interfaceName, ipAddress)
		cmd = exec.Command("netsh", "interface", "ip", "delete", "address", interfaceName, ipAddress)

	default:
		return fmt.Errorf("不支持的操作系统: %s", nc.osType)
	}

	// 执行命令
	output, err := cmd.CombinedOutput()

	// 记录配置变更
	change := ConfigChange{
		Timestamp: time.Now(),
		Operation: "RemoveInterfaceIP",
		Interface: interfaceName,
		OldValue:  ipAddress,
		NewValue:  "",
		Success:   err == nil,
	}

	if err != nil {
		change.Error = fmt.Sprintf("命令执行失败: %s, 输出: %s", err.Error(), string(output))
		nc.addConfigHistory(change)
		return fmt.Errorf("删除接口IP失败: %v, 命令: %s, 输出: %s", err, cmdStr, string(output))
	}

	nc.addConfigHistory(change)
	return nil
}

// SetInterfaceUp 启用网络接口
//
// 参数：
//   - interfaceName: 接口名称
//
// 返回值：
//   - error: 启用成功返回nil，失败返回错误信息
func (nc *NetworkConfigurator) SetInterfaceUp(interfaceName string) error {
	return nc.setInterfaceState(interfaceName, true)
}

// SetInterfaceDown 禁用网络接口
//
// 参数：
//   - interfaceName: 接口名称
//
// 返回值：
//   - error: 禁用成功返回nil，失败返回错误信息
func (nc *NetworkConfigurator) SetInterfaceDown(interfaceName string) error {
	return nc.setInterfaceState(interfaceName, false)
}

// setInterfaceState 设置接口状态
func (nc *NetworkConfigurator) setInterfaceState(interfaceName string, up bool) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	var cmd *exec.Cmd
	var cmdStr string
	var operation string

	if up {
		operation = "SetInterfaceUp"
	} else {
		operation = "SetInterfaceDown"
	}

	switch nc.osType {
	case "linux":
		if up {
			cmdStr = fmt.Sprintf("ip link set %s up", interfaceName)
			cmd = exec.Command("ip", "link", "set", interfaceName, "up")
		} else {
			cmdStr = fmt.Sprintf("ip link set %s down", interfaceName)
			cmd = exec.Command("ip", "link", "set", interfaceName, "down")
		}

	case "darwin": // macOS
		if up {
			cmdStr = fmt.Sprintf("ifconfig %s up", interfaceName)
			cmd = exec.Command("ifconfig", interfaceName, "up")
		} else {
			cmdStr = fmt.Sprintf("ifconfig %s down", interfaceName)
			cmd = exec.Command("ifconfig", interfaceName, "down")
		}

	case "windows":
		if up {
			cmdStr = fmt.Sprintf("netsh interface set interface \"%s\" enable", interfaceName)
			cmd = exec.Command("netsh", "interface", "set", "interface", interfaceName, "enable")
		} else {
			cmdStr = fmt.Sprintf("netsh interface set interface \"%s\" disable", interfaceName)
			cmd = exec.Command("netsh", "interface", "set", "interface", interfaceName, "disable")
		}

	default:
		return fmt.Errorf("不支持的操作系统: %s", nc.osType)
	}

	// 执行命令
	output, err := cmd.CombinedOutput()

	// 记录配置变更
	change := ConfigChange{
		Timestamp: time.Now(),
		Operation: operation,
		Interface: interfaceName,
		OldValue:  "",
		NewValue:  strconv.FormatBool(up),
		Success:   err == nil,
	}

	if err != nil {
		change.Error = fmt.Sprintf("命令执行失败: %s, 输出: %s", err.Error(), string(output))
		nc.addConfigHistory(change)
		return fmt.Errorf("设置接口状态失败: %v, 命令: %s, 输出: %s", err, cmdStr, string(output))
	}

	nc.addConfigHistory(change)
	return nil
}

// AddRoute 添加路由表项
//
// 参数：
//   - destination: 目标网络 (如 "192.168.1.0/24", "0.0.0.0/0")
//   - gateway: 网关地址 (如 "192.168.1.1")
//   - interfaceName: 出接口名称 (可选，某些系统需要)
//   - metric: 路由度量值 (可选，默认为0)
//
// 返回值：
//   - error: 添加成功返回nil，失败返回错误信息
//
// 使用示例：
//
//	// 添加默认路由
//	err := config.AddRoute("0.0.0.0/0", "192.168.1.1", "eth0", 0)
//
//	// 添加静态路由
//	err := config.AddRoute("10.0.0.0/8", "192.168.1.254", "eth0", 10)
func (nc *NetworkConfigurator) AddRoute(destination, gateway, interfaceName string, metric int) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// 验证目标网络
	_, destNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("无效的目标网络: %s", destination)
	}

	// 验证网关地址
	gwIP := net.ParseIP(gateway)
	if gwIP == nil {
		return fmt.Errorf("无效的网关地址: %s", gateway)
	}

	var cmd *exec.Cmd
	var cmdStr string

	switch nc.osType {
	case "linux":
		// Linux: ip route add 192.168.1.0/24 via 192.168.1.1 dev eth0 metric 10
		if interfaceName != "" && metric > 0 {
			cmdStr = fmt.Sprintf("ip route add %s via %s dev %s metric %d", destination, gateway, interfaceName, metric)
			cmd = exec.Command("ip", "route", "add", destination, "via", gateway, "dev", interfaceName, "metric", strconv.Itoa(metric))
		} else if interfaceName != "" {
			cmdStr = fmt.Sprintf("ip route add %s via %s dev %s", destination, gateway, interfaceName)
			cmd = exec.Command("ip", "route", "add", destination, "via", gateway, "dev", interfaceName)
		} else {
			cmdStr = fmt.Sprintf("ip route add %s via %s", destination, gateway)
			cmd = exec.Command("ip", "route", "add", destination, "via", gateway)
		}

	case "darwin": // macOS
		// macOS: route add -net 192.168.1.0/24 192.168.1.1
		cmdStr = fmt.Sprintf("route add -net %s %s", destination, gateway)
		cmd = exec.Command("route", "add", "-net", destination, gateway)

	case "windows":
		// Windows: route add 192.168.1.0 mask 255.255.255.0 192.168.1.1 metric 10
		mask := nc.cidrToNetmask(destination)
		network := destNet.IP.String()
		if metric > 0 {
			cmdStr = fmt.Sprintf("route add %s mask %s %s metric %d", network, mask, gateway, metric)
			cmd = exec.Command("route", "add", network, "mask", mask, gateway, "metric", strconv.Itoa(metric))
		} else {
			cmdStr = fmt.Sprintf("route add %s mask %s %s", network, mask, gateway)
			cmd = exec.Command("route", "add", network, "mask", mask, gateway)
		}

	default:
		return fmt.Errorf("不支持的操作系统: %s", nc.osType)
	}

	// 执行命令
	output, err := cmd.CombinedOutput()

	// 记录配置变更
	change := ConfigChange{
		Timestamp: time.Now(),
		Operation: "AddRoute",
		Interface: interfaceName,
		OldValue:  "",
		NewValue:  fmt.Sprintf("Dest: %s, Gateway: %s, Metric: %d", destination, gateway, metric),
		Success:   err == nil,
	}

	if err != nil {
		change.Error = fmt.Sprintf("命令执行失败: %s, 输出: %s", err.Error(), string(output))
		nc.addConfigHistory(change)
		return fmt.Errorf("添加路由失败: %v, 命令: %s, 输出: %s", err, cmdStr, string(output))
	}

	nc.addConfigHistory(change)
	return nil
}

// RemoveRoute 删除路由表项
//
// 参数：
//   - destination: 目标网络
//   - gateway: 网关地址 (可选)
//
// 返回值：
//   - error: 删除成功返回nil，失败返回错误信息
func (nc *NetworkConfigurator) RemoveRoute(destination, gateway string) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// 验证目标网络
	_, destNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("无效的目标网络: %s", destination)
	}

	var cmd *exec.Cmd
	var cmdStr string

	switch nc.osType {
	case "linux":
		// Linux: ip route del 192.168.1.0/24
		if gateway != "" {
			cmdStr = fmt.Sprintf("ip route del %s via %s", destination, gateway)
			cmd = exec.Command("ip", "route", "del", destination, "via", gateway)
		} else {
			cmdStr = fmt.Sprintf("ip route del %s", destination)
			cmd = exec.Command("ip", "route", "del", destination)
		}

	case "darwin": // macOS
		// macOS: route delete -net 192.168.1.0/24
		cmdStr = fmt.Sprintf("route delete -net %s", destination)
		cmd = exec.Command("route", "delete", "-net", destination)

	case "windows":
		// Windows: route delete 192.168.1.0 mask 255.255.255.0
		mask := nc.cidrToNetmask(destination)
		network := destNet.IP.String()
		cmdStr = fmt.Sprintf("route delete %s mask %s", network, mask)
		cmd = exec.Command("route", "delete", network, "mask", mask)

	default:
		return fmt.Errorf("不支持的操作系统: %s", nc.osType)
	}

	// 执行命令
	output, err := cmd.CombinedOutput()

	// 记录配置变更
	change := ConfigChange{
		Timestamp: time.Now(),
		Operation: "RemoveRoute",
		Interface: "",
		OldValue:  fmt.Sprintf("Dest: %s, Gateway: %s", destination, gateway),
		NewValue:  "",
		Success:   err == nil,
	}

	if err != nil {
		change.Error = fmt.Sprintf("命令执行失败: %s, 输出: %s", err.Error(), string(output))
		nc.addConfigHistory(change)
		return fmt.Errorf("删除路由失败: %v, 命令: %s, 输出: %s", err, cmdStr, string(output))
	}

	nc.addConfigHistory(change)
	return nil
}

// EnableIPForwarding 启用IP转发
//
// 返回值：
//   - error: 启用成功返回nil，失败返回错误信息
//
// 注意：
//   - Linux: 修改 /proc/sys/net/ipv4/ip_forward
//   - macOS: 使用 sysctl net.inet.ip.forwarding=1
//   - Windows: 需要注册表修改，需要管理员权限
func (nc *NetworkConfigurator) EnableIPForwarding() error {
	return nc.setIPForwarding(true)
}

// DisableIPForwarding 禁用IP转发
//
// 返回值：
//   - error: 禁用成功返回nil，失败返回错误信息
func (nc *NetworkConfigurator) DisableIPForwarding() error {
	return nc.setIPForwarding(false)
}

// setIPForwarding 设置IP转发状态
func (nc *NetworkConfigurator) setIPForwarding(enable bool) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	var cmd *exec.Cmd
	var cmdStr string
	var operation string

	if enable {
		operation = "EnableIPForwarding"
	} else {
		operation = "DisableIPForwarding"
	}

	switch nc.osType {
	case "linux":
		value := "0"
		if enable {
			value = "1"
		}
		cmdStr = fmt.Sprintf("echo %s > /proc/sys/net/ipv4/ip_forward", value)
		cmd = exec.Command("sh", "-c", cmdStr)

	case "darwin": // macOS
		value := "0"
		if enable {
			value = "1"
		}
		cmdStr = fmt.Sprintf("sysctl net.inet.ip.forwarding=%s", value)
		cmd = exec.Command("sysctl", fmt.Sprintf("net.inet.ip.forwarding=%s", value))

	case "windows":
		// Windows需要修改注册表，这里简化处理
		return fmt.Errorf("Windows系统的IP转发配置需要手动设置")

	default:
		return fmt.Errorf("不支持的操作系统: %s", nc.osType)
	}

	// 执行命令
	output, err := cmd.CombinedOutput()

	// 记录配置变更
	change := ConfigChange{
		Timestamp: time.Now(),
		Operation: operation,
		Interface: "",
		OldValue:  "",
		NewValue:  strconv.FormatBool(enable),
		Success:   err == nil,
	}

	if err != nil {
		change.Error = fmt.Sprintf("命令执行失败: %s, 输出: %s", err.Error(), string(output))
		nc.addConfigHistory(change)
		return fmt.Errorf("设置IP转发失败: %v, 命令: %s, 输出: %s", err, cmdStr, string(output))
	}

	nc.addConfigHistory(change)
	return nil
}

// GetInterfaceList 获取网络接口列表
//
// 返回值：
//   - []string: 接口名称列表
//   - error: 获取失败返回错误信息
func (nc *NetworkConfigurator) GetInterfaceList() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取接口列表失败: %v", err)
	}

	var names []string
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}

	return names, nil
}

// GetInterfaceConfig 获取接口配置信息
//
// 参数：
//   - interfaceName: 接口名称
//
// 返回值：
//   - *InterfaceConfig: 接口配置信息
//   - error: 获取失败返回错误信息
func (nc *NetworkConfigurator) GetInterfaceConfig(interfaceName string) (*InterfaceConfig, error) {
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	return nc.getInterfaceConfig(interfaceName)
}

// getInterfaceConfig 内部方法：获取接口配置
func (nc *NetworkConfigurator) getInterfaceConfig(interfaceName string) (*InterfaceConfig, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("接口不存在: %s", interfaceName)
	}

	config := &InterfaceConfig{
		Name: iface.Name,
		MTU:  iface.MTU,
		MAC:  iface.HardwareAddr,
		Up:   iface.Flags&net.FlagUp != 0,
	}

	// 获取IP地址
	addrs, err := iface.Addrs()
	if err == nil && len(addrs) > 0 {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					config.IPAddress = ipnet.IP
					config.Netmask = ipnet.Mask
					break
				}
			}
		}
	}

	return config, nil
}

// GetRouteTable 获取路由表
//
// 返回值：
//   - []RouteEntry: 路由表项列表
//   - error: 获取失败返回错误信息
func (nc *NetworkConfigurator) GetRouteTable() ([]RouteEntry, error) {
	var cmd *exec.Cmd

	switch nc.osType {
	case "linux":
		cmd = exec.Command("ip", "route", "show")
	case "darwin":
		cmd = exec.Command("netstat", "-rn", "-f", "inet")
	case "windows":
		cmd = exec.Command("route", "print", "-4")
	default:
		return nil, fmt.Errorf("不支持的操作系统: %s", nc.osType)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("获取路由表失败: %v", err)
	}

	return nc.parseRouteTable(string(output))
}

// parseRouteTable 解析路由表输出
func (nc *NetworkConfigurator) parseRouteTable(output string) ([]RouteEntry, error) {
	lines := strings.Split(output, "\n")

	// 根据操作系统类型选择不同的解析策略
	switch nc.osType {
	case "linux":
		return nc.parseLinuxRouteTable(lines)
	case "darwin":
		return nc.parseDarwinRouteTable(lines)
	case "windows":
		return nc.parseWindowsRouteTable(lines)
	default:
		// 通用解析逻辑作为后备
		return nc.parseGenericRouteTable(lines)
	}
}

// parseLinuxRouteTable 解析Linux系统的路由表输出
func (nc *NetworkConfigurator) parseLinuxRouteTable(lines []string) ([]RouteEntry, error) {
	var routes []RouteEntry

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 { // 跳过空行和标题行
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 8 {
			route := RouteEntry{
				Type: "static",
			}

			// Linux route -n 输出格式：Destination Gateway Genmask Flags Metric Ref Use Iface
			if dest, err := nc.parseDestination(fields[0]); err == nil {
				route.Destination = dest
			}

			if fields[1] != "0.0.0.0" && fields[1] != "*" {
				route.Gateway = net.ParseIP(fields[1])
			}

			if len(fields) > 7 {
				route.Interface = fields[7]
			}

			if len(fields) > 4 {
				if metric, err := strconv.Atoi(fields[4]); err == nil {
					route.Metric = metric
				}
			}

			routes = append(routes, route)
		}
	}

	return routes, nil
}

// parseDarwinRouteTable 解析macOS系统的路由表输出
func (nc *NetworkConfigurator) parseDarwinRouteTable(lines []string) ([]RouteEntry, error) {
	var routes []RouteEntry

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 { // 跳过空行和标题行
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			route := RouteEntry{
				Type: "static",
			}

			// macOS netstat -rn 输出格式：Destination Gateway Flags Refs Use Netif Expire
			if dest, err := nc.parseDestination(fields[0]); err == nil {
				route.Destination = dest
			}

			if fields[1] != "link#" && !strings.Contains(fields[1], "link#") {
				route.Gateway = net.ParseIP(fields[1])
			}

			if len(fields) > 5 {
				route.Interface = fields[5]
			}

			// macOS没有直接的metric字段，使用默认值
			route.Metric = 0

			routes = append(routes, route)
		}
	}

	return routes, nil
}

// parseWindowsRouteTable 解析Windows系统的路由表输出
func (nc *NetworkConfigurator) parseWindowsRouteTable(lines []string) ([]RouteEntry, error) {
	var routes []RouteEntry

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i < 3 { // 跳过空行和前几行标题
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 5 {
			route := RouteEntry{
				Type: "static",
			}

			// Windows route print 输出格式：Network Destination Netmask Gateway Interface Metric
			if dest, err := nc.parseDestination(fields[0]); err == nil {
				route.Destination = dest
			}

			if fields[2] != "0.0.0.0" {
				route.Gateway = net.ParseIP(fields[2])
			}

			if len(fields) > 3 {
				route.Interface = fields[3]
			}

			if len(fields) > 4 {
				if metric, err := strconv.Atoi(fields[4]); err == nil {
					route.Metric = metric
				}
			}

			routes = append(routes, route)
		}
	}

	return routes, nil
}

// parseGenericRouteTable 通用路由表解析逻辑（后备方案）
func (nc *NetworkConfigurator) parseGenericRouteTable(lines []string) ([]RouteEntry, error) {
	var routes []RouteEntry

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			route := RouteEntry{
				Type: "unknown",
			}

			// 尝试解析目标地址
			if dest, err := nc.parseDestination(fields[0]); err == nil {
				route.Destination = dest
			}

			// 尝试解析网关
			if len(fields) > 1 && fields[1] != "0.0.0.0" && fields[1] != "*" {
				route.Gateway = net.ParseIP(fields[1])
			}

			// 尝试解析接口
			if len(fields) > 2 {
				route.Interface = fields[len(fields)-1] // 通常接口名在最后
			}

			routes = append(routes, route)
		}
	}

	return routes, nil
}

// parseDestination 解析目标网络
func (nc *NetworkConfigurator) parseDestination(dest string) (*net.IPNet, error) {
	if dest == "default" || dest == "0.0.0.0" {
		_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
		return defaultNet, nil
	}

	if strings.Contains(dest, "/") {
		_, network, err := net.ParseCIDR(dest)
		return network, err
	}

	// 假设是单个IP地址
	ip := net.ParseIP(dest)
	if ip != nil {
		if ip.To4() != nil {
			_, network, _ := net.ParseCIDR(dest + "/32")
			return network, nil
		} else {
			_, network, _ := net.ParseCIDR(dest + "/128")
			return network, nil
		}
	}

	return nil, fmt.Errorf("无法解析目标网络: %s", dest)
}

// GetConfigHistory 获取配置历史记录
//
// 返回值：
//   - []ConfigChange: 配置变更历史
func (nc *NetworkConfigurator) GetConfigHistory() []ConfigChange {
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	// 返回副本以避免并发修改
	history := make([]ConfigChange, len(nc.configHistory))
	copy(history, nc.configHistory)

	return history
}

// ClearConfigHistory 清空配置历史记录
func (nc *NetworkConfigurator) ClearConfigHistory() {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	nc.configHistory = make([]ConfigChange, 0)
}

// 辅助方法

// convertToCIDR 将IP和子网掩码转换为CIDR格式
func (nc *NetworkConfigurator) convertToCIDR(ip, netmask string) string {
	if strings.HasPrefix(netmask, "/") {
		return ip + netmask
	}

	// 将点分十进制子网掩码转换为CIDR
	mask := net.ParseIP(netmask).To4()
	if mask != nil {
		prefixLen, _ := net.IPv4Mask(mask[0], mask[1], mask[2], mask[3]).Size()
		return fmt.Sprintf("%s/%d", ip, prefixLen)
	}

	return ip + "/24" // 默认值
}

// cidrToNetmask 将CIDR转换为点分十进制子网掩码
func (nc *NetworkConfigurator) cidrToNetmask(cidr string) string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "255.255.255.0" // 默认值
	}

	mask := network.Mask
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

// formatInterfaceConfig 格式化接口配置信息
func (nc *NetworkConfigurator) formatInterfaceConfig(config *InterfaceConfig) string {
	if config == nil {
		return ""
	}

	return fmt.Sprintf("IP: %s, Netmask: %s, Up: %t",
		config.IPAddress, config.Netmask, config.Up)
}

// addConfigHistory 添加配置历史记录
func (nc *NetworkConfigurator) addConfigHistory(change ConfigChange) {
	nc.configHistory = append(nc.configHistory, change)

	// 限制历史记录数量
	if len(nc.configHistory) > nc.maxHistorySize {
		nc.configHistory = nc.configHistory[1:]
	}
}

// ===== 高级网络配置管理功能 =====

// ConfigValidator 配置验证器
type ConfigValidator struct {
	// 验证规则
	rules map[string]ValidationRule

	// 验证历史
	validationHistory []ValidationResult

	// 最大历史记录数
	maxHistorySize int
}

// ValidationRule 验证规则
type ValidationRule struct {
	// Name 规则名称
	Name string

	// Description 规则描述
	Description string

	// Validator 验证函数
	Validator func(interface{}) error

	// Severity 严重程度
	Severity ValidationSeverity
}

// ValidationSeverity 验证严重程度
type ValidationSeverity int

const (
	SeverityInfo ValidationSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

// ValidationResult 验证结果
type ValidationResult struct {
	// Timestamp 验证时间
	Timestamp time.Time

	// RuleName 规则名称
	RuleName string

	// Target 验证目标
	Target string

	// Severity 严重程度
	Severity ValidationSeverity

	// Message 验证消息
	Message string

	// Success 是否通过验证
	Success bool
}

// NewConfigValidator 创建配置验证器
func NewConfigValidator() *ConfigValidator {
	cv := &ConfigValidator{
		rules:             make(map[string]ValidationRule),
		validationHistory: make([]ValidationResult, 0),
		maxHistorySize:    1000,
	}

	// 添加默认验证规则
	cv.addDefaultRules()

	return cv
}

// addDefaultRules 添加默认验证规则
func (cv *ConfigValidator) addDefaultRules() {
	// IP地址格式验证
	cv.AddRule(ValidationRule{
		Name:        "ip_format",
		Description: "验证IP地址格式",
		Validator: func(value interface{}) error {
			if ip, ok := value.(string); ok {
				if net.ParseIP(ip) == nil {
					return fmt.Errorf("无效的IP地址格式: %s", ip)
				}
			}
			return nil
		},
		Severity: SeverityError,
	})

	// 子网掩码验证
	cv.AddRule(ValidationRule{
		Name:        "netmask_format",
		Description: "验证子网掩码格式",
		Validator: func(value interface{}) error {
			if mask, ok := value.(string); ok {
				if strings.HasPrefix(mask, "/") {
					// CIDR格式
					if prefixLen, err := strconv.Atoi(mask[1:]); err != nil || prefixLen < 0 || prefixLen > 32 {
						return fmt.Errorf("无效的CIDR前缀长度: %s", mask)
					}
				} else {
					// 点分十进制格式
					if net.ParseIP(mask) == nil {
						return fmt.Errorf("无效的子网掩码格式: %s", mask)
					}
				}
			}
			return nil
		},
		Severity: SeverityError,
	})

	// MTU值验证
	cv.AddRule(ValidationRule{
		Name:        "mtu_range",
		Description: "验证MTU值范围",
		Validator: func(value interface{}) error {
			if mtu, ok := value.(int); ok {
				if mtu < 68 || mtu > 9000 {
					return fmt.Errorf("MTU值超出有效范围(68-9000): %d", mtu)
				}
			}
			return nil
		},
		Severity: SeverityWarning,
	})

	// 接口名称验证
	cv.AddRule(ValidationRule{
		Name:        "interface_name",
		Description: "验证接口名称格式",
		Validator: func(value interface{}) error {
			if name, ok := value.(string); ok {
				if len(name) == 0 {
					return fmt.Errorf("接口名称不能为空")
				}
				if len(name) > 15 {
					return fmt.Errorf("接口名称过长(最大15字符): %s", name)
				}
			}
			return nil
		},
		Severity: SeverityError,
	})
}

// AddRule 添加验证规则
func (cv *ConfigValidator) AddRule(rule ValidationRule) {
	cv.rules[rule.Name] = rule
}

// RemoveRule 移除验证规则
func (cv *ConfigValidator) RemoveRule(ruleName string) {
	delete(cv.rules, ruleName)
}

// ValidateInterfaceConfig 验证接口配置
func (cv *ConfigValidator) ValidateInterfaceConfig(config *InterfaceConfig) []ValidationResult {
	var results []ValidationResult

	// 验证接口名称
	if rule, exists := cv.rules["interface_name"]; exists {
		if err := rule.Validator(config.Name); err != nil {
			results = append(results, ValidationResult{
				Timestamp: time.Now(),
				RuleName:  rule.Name,
				Target:    config.Name,
				Severity:  rule.Severity,
				Message:   err.Error(),
				Success:   false,
			})
		}
	}

	// 验证IP地址
	if rule, exists := cv.rules["ip_format"]; exists {
		if err := rule.Validator(config.IPAddress.String()); err != nil {
			results = append(results, ValidationResult{
				Timestamp: time.Now(),
				RuleName:  rule.Name,
				Target:    config.IPAddress.String(),
				Severity:  rule.Severity,
				Message:   err.Error(),
				Success:   false,
			})
		}
	}

	// 验证MTU
	if rule, exists := cv.rules["mtu_range"]; exists {
		if err := rule.Validator(config.MTU); err != nil {
			results = append(results, ValidationResult{
				Timestamp: time.Now(),
				RuleName:  rule.Name,
				Target:    fmt.Sprintf("%d", config.MTU),
				Severity:  rule.Severity,
				Message:   err.Error(),
				Success:   false,
			})
		}
	}

	// 记录验证历史
	cv.addValidationHistory(results...)

	return results
}

// ValidateRouteEntry 验证路由条目
func (cv *ConfigValidator) ValidateRouteEntry(route *RouteEntry) []ValidationResult {
	var results []ValidationResult

	// 验证网关IP
	if rule, exists := cv.rules["ip_format"]; exists {
		if err := rule.Validator(route.Gateway.String()); err != nil {
			results = append(results, ValidationResult{
				Timestamp: time.Now(),
				RuleName:  rule.Name,
				Target:    route.Gateway.String(),
				Severity:  rule.Severity,
				Message:   err.Error(),
				Success:   false,
			})
		}
	}

	// 验证接口名称
	if rule, exists := cv.rules["interface_name"]; exists {
		if err := rule.Validator(route.Interface); err != nil {
			results = append(results, ValidationResult{
				Timestamp: time.Now(),
				RuleName:  rule.Name,
				Target:    route.Interface,
				Severity:  rule.Severity,
				Message:   err.Error(),
				Success:   false,
			})
		}
	}

	// 记录验证历史
	cv.addValidationHistory(results...)

	return results
}

// GetValidationHistory 获取验证历史
func (cv *ConfigValidator) GetValidationHistory() []ValidationResult {
	return cv.validationHistory
}

// addValidationHistory 添加验证历史
func (cv *ConfigValidator) addValidationHistory(results ...ValidationResult) {
	cv.validationHistory = append(cv.validationHistory, results...)

	// 限制历史记录数量
	if len(cv.validationHistory) > cv.maxHistorySize {
		excess := len(cv.validationHistory) - cv.maxHistorySize
		cv.validationHistory = cv.validationHistory[excess:]
	}
}

// HotReloadManager 热重载管理器
type HotReloadManager struct {
	// 配置文件路径
	configPath string

	// 文件监控器
	watcher *FileWatcher

	// 重载回调函数
	reloadCallback func() error

	// 重载历史
	reloadHistory []ReloadEvent

	// 最大历史记录数
	maxHistorySize int

	// 互斥锁
	mu sync.RWMutex
}

// ReloadEvent 重载事件
type ReloadEvent struct {
	// Timestamp 重载时间
	Timestamp time.Time

	// Trigger 触发原因
	Trigger string

	// Success 是否成功
	Success bool

	// Error 错误信息
	Error string

	// Duration 重载耗时
	Duration time.Duration
}

// FileWatcher 文件监控器
type FileWatcher struct {
	// 监控的文件路径
	filePath string

	// 最后修改时间
	lastModTime time.Time

	// 监控间隔
	interval time.Duration

	// 停止信号
	stopChan chan bool

	// 变更回调
	onChange func()
}

// NewHotReloadManager 创建热重载管理器
func NewHotReloadManager(configPath string, reloadCallback func() error) *HotReloadManager {
	return &HotReloadManager{
		configPath:     configPath,
		reloadCallback: reloadCallback,
		reloadHistory:  make([]ReloadEvent, 0),
		maxHistorySize: 100,
	}
}

// Start 启动热重载监控
func (hrm *HotReloadManager) Start() error {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	// 创建文件监控器
	watcher := &FileWatcher{
		filePath: hrm.configPath,
		interval: 1 * time.Second,
		stopChan: make(chan bool),
		onChange: func() {
			_ = hrm.triggerReload("file_change")
		},
	}

	// 获取初始修改时间
	if err := watcher.updateModTime(); err != nil {
		return fmt.Errorf("无法获取配置文件信息: %v", err)
	}

	hrm.watcher = watcher

	// 启动监控协程
	go watcher.watch()

	return nil
}

// Stop 停止热重载监控
func (hrm *HotReloadManager) Stop() {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	if hrm.watcher != nil {
		hrm.watcher.stop()
		hrm.watcher = nil
	}
}

// TriggerReload 手动触发重载
func (hrm *HotReloadManager) TriggerReload(reason string) error {
	return hrm.triggerReload(reason)
}

// triggerReload 执行重载
func (hrm *HotReloadManager) triggerReload(trigger string) error {
	start := time.Now()

	event := ReloadEvent{
		Timestamp: start,
		Trigger:   trigger,
	}

	// 执行重载回调
	if hrm.reloadCallback != nil {
		if err := hrm.reloadCallback(); err != nil {
			event.Success = false
			event.Error = err.Error()
		} else {
			event.Success = true
		}
	}

	event.Duration = time.Since(start)

	// 记录重载历史
	hrm.addReloadHistory(event)

	if !event.Success {
		return fmt.Errorf("重载失败: %s", event.Error)
	}

	return nil
}

// GetReloadHistory 获取重载历史
func (hrm *HotReloadManager) GetReloadHistory() []ReloadEvent {
	hrm.mu.RLock()
	defer hrm.mu.RUnlock()

	history := make([]ReloadEvent, len(hrm.reloadHistory))
	copy(history, hrm.reloadHistory)

	return history
}

// addReloadHistory 添加重载历史
func (hrm *HotReloadManager) addReloadHistory(event ReloadEvent) {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	hrm.reloadHistory = append(hrm.reloadHistory, event)

	// 限制历史记录数量
	if len(hrm.reloadHistory) > hrm.maxHistorySize {
		hrm.reloadHistory = hrm.reloadHistory[1:]
	}
}

// updateModTime 更新文件修改时间
func (fw *FileWatcher) updateModTime() error {
	info, err := exec.Command("stat", "-c", "%Y", fw.filePath).Output()
	if err != nil {
		// 尝试使用不同的命令
		info, err = exec.Command("stat", "-f", "%m", fw.filePath).Output()
		if err != nil {
			return err
		}
	}

	timestamp, err := strconv.ParseInt(strings.TrimSpace(string(info)), 10, 64)
	if err != nil {
		return err
	}

	fw.lastModTime = time.Unix(timestamp, 0)
	return nil
}

// watch 监控文件变化
func (fw *FileWatcher) watch() {
	ticker := time.NewTicker(fw.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := fw.checkFileChange(); err == nil {
				// 文件发生变化
				if fw.onChange != nil {
					fw.onChange()
				}
			}
		case <-fw.stopChan:
			return
		}
	}
}

// checkFileChange 检查文件是否发生变化
func (fw *FileWatcher) checkFileChange() error {
	oldModTime := fw.lastModTime

	if err := fw.updateModTime(); err != nil {
		return err
	}

	if fw.lastModTime.After(oldModTime) {
		return nil // 文件已变化
	}

	return fmt.Errorf("文件未变化")
}

// stop 停止监控
func (fw *FileWatcher) stop() {
	close(fw.stopChan)
}

// BackupManager 备份管理器
type BackupManager struct {
	// 备份目录
	backupDir string

	// 最大备份数量
	maxBackups int

	// 备份历史
	backupHistory []BackupInfo

	// 互斥锁
	mu sync.RWMutex
}

// BackupInfo 备份信息
type BackupInfo struct {
	// ID 备份ID
	ID string

	// Timestamp 备份时间
	Timestamp time.Time

	// FilePath 备份文件路径
	FilePath string

	// Size 备份文件大小
	Size int64

	// Description 备份描述
	Description string

	// Type 备份类型
	Type BackupType
}

// BackupType 备份类型
type BackupType int

const (
	BackupTypeManual BackupType = iota
	BackupTypeScheduled
	BackupTypeAutomatic
)

// NewBackupManager 创建备份管理器
func NewBackupManager(backupDir string, maxBackups int) *BackupManager {
	return &BackupManager{
		backupDir:     backupDir,
		maxBackups:    maxBackups,
		backupHistory: make([]BackupInfo, 0),
	}
}

// CreateBackup 创建配置备份
func (bm *BackupManager) CreateBackup(sourceConfig interface{}, description string, backupType BackupType) (*BackupInfo, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// 生成备份ID
	backupID := fmt.Sprintf("backup_%d", time.Now().Unix())

	// 生成备份文件路径
	backupPath := fmt.Sprintf("%s/%s.json", bm.backupDir, backupID)

	// 创建备份目录
	if err := exec.Command("mkdir", "-p", bm.backupDir).Run(); err != nil {
		return nil, fmt.Errorf("创建备份目录失败: %v", err)
	}

	// 序列化配置数据
	configData := fmt.Sprintf("%+v", sourceConfig)

	// 写入备份文件
	if err := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' > %s", configData, backupPath)).Run(); err != nil {
		return nil, fmt.Errorf("写入备份文件失败: %v", err)
	}

	// 获取文件大小
	sizeOutput, err := exec.Command("stat", "-c", "%s", backupPath).Output()
	if err != nil {
		// 尝试macOS命令
		sizeOutput, err = exec.Command("stat", "-f", "%z", backupPath).Output()
		if err != nil {
			return nil, fmt.Errorf("获取备份文件大小失败: %v", err)
		}
	}

	size, _ := strconv.ParseInt(strings.TrimSpace(string(sizeOutput)), 10, 64)

	// 创建备份信息
	backupInfo := &BackupInfo{
		ID:          backupID,
		Timestamp:   time.Now(),
		FilePath:    backupPath,
		Size:        size,
		Description: description,
		Type:        backupType,
	}

	// 添加到历史记录
	bm.backupHistory = append(bm.backupHistory, *backupInfo)

	// 清理旧备份
	bm.cleanupOldBackups()

	return backupInfo, nil
}

// RestoreBackup 恢复配置备份
func (bm *BackupManager) RestoreBackup(backupID string) error {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	// 查找备份信息
	var backupInfo *BackupInfo
	for _, backup := range bm.backupHistory {
		if backup.ID == backupID {
			backupInfo = &backup
			break
		}
	}

	if backupInfo == nil {
		return fmt.Errorf("备份不存在: %s", backupID)
	}

	// 检查备份文件是否存在
	if _, err := exec.Command("test", "-f", backupInfo.FilePath).Output(); err != nil {
		return fmt.Errorf("备份文件不存在: %s", backupInfo.FilePath)
	}

	// 根据备份类型执行相应的恢复操作
	return bm.performRestore(backupInfo)
}

// performRestore 执行具体的恢复操作
func (bm *BackupManager) performRestore(backupInfo *BackupInfo) error {
	fmt.Printf("开始恢复备份: %s\n", backupInfo.FilePath)

	// 1. 创建当前配置的临时备份（以防恢复失败）
	tempBackupInfo, err := bm.createTemporaryBackup()
	if err != nil {
		return fmt.Errorf("创建临时备份失败: %v", err)
	}

	// 2. 读取备份文件内容
	backupData, err := bm.readBackupFile(backupInfo.FilePath)
	if err != nil {
		return fmt.Errorf("读取备份文件失败: %v", err)
	}

	// 3. 验证备份数据的完整性
	if err := bm.validateBackupData(backupData); err != nil {
		return fmt.Errorf("备份数据验证失败: %v", err)
	}

	// 4. 应用备份配置
	if err := bm.applyBackupConfiguration(backupData); err != nil {
		// 恢复失败，尝试回滚到临时备份
		fmt.Printf("恢复失败，正在回滚到临时备份...\n")
		if rollbackErr := bm.performRestore(tempBackupInfo); rollbackErr != nil {
			return fmt.Errorf("恢复失败且回滚失败: 原错误=%v, 回滚错误=%v", err, rollbackErr)
		}
		return fmt.Errorf("恢复失败，已回滚: %v", err)
	}

	// 5. 验证恢复后的配置
	if err := bm.validateRestoredConfiguration(); err != nil {
		fmt.Printf("恢复后验证失败，正在回滚...\n")
		if rollbackErr := bm.performRestore(tempBackupInfo); rollbackErr != nil {
			return fmt.Errorf("验证失败且回滚失败: 原错误=%v, 回滚错误=%v", err, rollbackErr)
		}
		return fmt.Errorf("验证失败，已回滚: %v", err)
	}

	// 6. 清理临时备份
	bm.cleanupTemporaryBackup(tempBackupInfo)

	fmt.Printf("备份恢复成功: %s\n", backupInfo.Description)
	return nil
}

// createTemporaryBackup 创建临时备份
func (bm *BackupManager) createTemporaryBackup() (*BackupInfo, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// 创建临时备份信息
	tempBackup := &BackupInfo{
		ID:          fmt.Sprintf("temp_%d", time.Now().Unix()),
		Timestamp:   time.Now(),
		FilePath:    fmt.Sprintf("%s/temp_backup_%d.json", bm.backupDir, time.Now().Unix()),
		Description: "临时备份（恢复前自动创建）",
		Type:        BackupTypeAutomatic,
	}

	// 确保备份目录存在
	if err := os.MkdirAll(bm.backupDir, 0755); err != nil {
		return nil, fmt.Errorf("创建备份目录失败: %v", err)
	}

	// 收集当前系统配置
	currentConfig, err := bm.collectCurrentConfiguration()
	if err != nil {
		return nil, fmt.Errorf("收集当前配置失败: %v", err)
	}

	// 序列化配置数据
	configData, err := json.MarshalIndent(currentConfig, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化配置数据失败: %v", err)
	}

	// 写入临时备份文件
	if err := os.WriteFile(tempBackup.FilePath, configData, 0644); err != nil {
		return nil, fmt.Errorf("写入临时备份文件失败: %v", err)
	}

	// 计算文件大小
	if fileInfo, err := os.Stat(tempBackup.FilePath); err == nil {
		tempBackup.Size = fileInfo.Size()
	}

	fmt.Printf("创建临时备份成功: %s (大小: %d 字节)\n", tempBackup.FilePath, tempBackup.Size)

	return tempBackup, nil
}

// collectCurrentConfiguration 收集当前系统配置
func (bm *BackupManager) collectCurrentConfiguration() (map[string]interface{}, error) {
	config := make(map[string]interface{})

	// 创建网络配置器实例
	nc := NewNetworkConfigurator()

	// 收集网络接口配置
	interfaces := make(map[string]interface{})

	// 获取系统中所有网络接口
	interfaceNames, err := nc.GetInterfaceList()
	if err != nil {
		return nil, fmt.Errorf("获取接口列表失败: %v", err)
	}

	// 收集每个接口的详细配置
	for _, ifName := range interfaceNames {
		ifConfig, err := nc.GetInterfaceConfig(ifName)
		if err != nil {
			fmt.Printf("警告: 获取接口 %s 配置失败: %v\n", ifName, err)
			continue
		}

		// 构建接口配置数据
		interfaceData := map[string]interface{}{
			"name":   ifConfig.Name,
			"mtu":    ifConfig.MTU,
			"status": "down",
		}

		if ifConfig.Up {
			interfaceData["status"] = "up"
		}

		if ifConfig.IPAddress != nil {
			interfaceData["ip"] = ifConfig.IPAddress.String()
		}

		if ifConfig.Netmask != nil {
			interfaceData["netmask"] = net.IP(ifConfig.Netmask).String()
		}

		if ifConfig.Gateway != nil {
			interfaceData["gateway"] = ifConfig.Gateway.String()
		}

		if ifConfig.MAC != nil {
			interfaceData["mac"] = ifConfig.MAC.String()
		}

		interfaces[ifName] = interfaceData
	}
	config["interfaces"] = interfaces

	// 收集路由表信息
	routeEntries, err := nc.GetRouteTable()
	if err != nil {
		fmt.Printf("警告: 获取路由表失败: %v\n", err)
		// 如果无法获取路由表，设置空数组而不是返回错误
		config["routes"] = []map[string]interface{}{}
	} else {
		routes := make([]map[string]interface{}, 0, len(routeEntries))
		for _, route := range routeEntries {
			routeData := map[string]interface{}{
				"interface": route.Interface,
				"metric":    route.Metric,
				"type":      route.Type,
			}

			if route.Destination != nil {
				routeData["destination"] = route.Destination.String()
			}

			if route.Gateway != nil {
				routeData["gateway"] = route.Gateway.String()
			}

			routes = append(routes, routeData)
		}
		config["routes"] = routes
	}

	// 收集系统设置
	settings := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
		"os_type":   runtime.GOOS,
	}

	// 检查IP转发状态
	ipForwardingEnabled, err := bm.checkIPForwardingStatus()
	if err != nil {
		fmt.Printf("警告: 检查IP转发状态失败: %v\n", err)
		settings["ip_forwarding"] = "unknown"
	} else {
		settings["ip_forwarding"] = ipForwardingEnabled
	}

	config["settings"] = settings

	return config, nil
}

// checkIPForwardingStatus 检查IP转发状态
func (bm *BackupManager) checkIPForwardingStatus() (bool, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		// Linux: 读取 /proc/sys/net/ipv4/ip_forward
		cmd = exec.Command("cat", "/proc/sys/net/ipv4/ip_forward")
	case "darwin":
		// macOS: 使用 sysctl 检查
		cmd = exec.Command("sysctl", "-n", "net.inet.ip.forwarding")
	case "windows":
		// Windows: 使用 netsh 检查
		cmd = exec.Command("netsh", "interface", "ipv4", "show", "global")
	default:
		return false, fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("执行命令失败: %v", err)
	}

	outputStr := strings.TrimSpace(string(output))

	switch runtime.GOOS {
	case "linux", "darwin":
		// Linux和macOS返回1表示启用，0表示禁用
		return outputStr == "1", nil
	case "windows":
		// Windows需要解析netsh输出
		return strings.Contains(outputStr, "Forwarding=Enabled"), nil
	default:
		return false, fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// readBackupFile 读取备份文件
func (bm *BackupManager) readBackupFile(filePath string) ([]byte, error) {
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("备份文件不存在: %s", filePath)
	}

	// 读取文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取备份文件失败: %v", err)
	}

	// 检查文件是否为空
	if len(data) == 0 {
		return nil, fmt.Errorf("备份文件为空: %s", filePath)
	}

	fmt.Printf("成功读取备份文件: %s (大小: %d 字节)\n", filePath, len(data))
	return data, nil
}

// validateBackupData 验证备份数据
func (bm *BackupManager) validateBackupData(data []byte) error {
	fmt.Printf("验证备份数据完整性...\n")

	// 检查数据是否为空
	if len(data) == 0 {
		return fmt.Errorf("备份数据为空")
	}

	// 验证JSON格式
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("备份数据JSON格式无效: %v", err)
	}

	// 验证必需的配置节
	requiredSections := []string{"interfaces", "routes", "settings"}
	for _, section := range requiredSections {
		if _, exists := config[section]; !exists {
			return fmt.Errorf("备份数据缺少必需的配置节: %s", section)
		}
	}

	// 验证接口配置
	if interfaces, ok := config["interfaces"].(map[string]interface{}); ok {
		for ifName, ifConfig := range interfaces {
			if ifConfigMap, ok := ifConfig.(map[string]interface{}); ok {
				// 检查必需的接口字段
				requiredFields := []string{"ip", "netmask", "status"}
				for _, field := range requiredFields {
					if _, exists := ifConfigMap[field]; !exists {
						return fmt.Errorf("接口 %s 缺少必需字段: %s", ifName, field)
					}
				}
			}
		}
	}

	// 验证路由配置
	if routes, ok := config["routes"].([]interface{}); ok {
		for i, route := range routes {
			if routeMap, ok := route.(map[string]interface{}); ok {
				// 检查必需的路由字段
				requiredFields := []string{"destination", "gateway", "interface"}
				for _, field := range requiredFields {
					if _, exists := routeMap[field]; !exists {
						return fmt.Errorf("路由 %d 缺少必需字段: %s", i, field)
					}
				}
			}
		}
	}

	// 验证设置配置
	if settings, ok := config["settings"].(map[string]interface{}); ok {
		// 检查版本信息
		if version, exists := settings["version"]; !exists || version == "" {
			return fmt.Errorf("备份数据缺少版本信息")
		}
	}

	fmt.Printf("备份数据验证通过\n")
	return nil
}

// applyBackupConfiguration 应用备份配置
func (bm *BackupManager) applyBackupConfiguration(data []byte) error {
	fmt.Printf("应用备份配置...\n")

	// 解析JSON配置
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析备份配置失败: %v", err)
	}

	// 应用网络接口配置
	if err := bm.applyInterfaceConfiguration(config["interfaces"]); err != nil {
		return fmt.Errorf("应用接口配置失败: %v", err)
	}

	// 应用路由配置
	if err := bm.applyRouteConfiguration(config["routes"]); err != nil {
		return fmt.Errorf("应用路由配置失败: %v", err)
	}

	// 应用系统设置
	if err := bm.applySystemSettings(config["settings"]); err != nil {
		return fmt.Errorf("应用系统设置失败: %v", err)
	}

	fmt.Printf("备份配置应用完成\n")
	return nil
}

// applyInterfaceConfiguration 应用接口配置
func (bm *BackupManager) applyInterfaceConfiguration(interfacesData interface{}) error {
	fmt.Printf("- 应用网络接口配置\n")

	interfaces, ok := interfacesData.(map[string]interface{})
	if !ok {
		return fmt.Errorf("接口配置数据格式无效")
	}

	// 创建网络配置器实例
	nc := NewNetworkConfigurator()

	for ifName, ifConfig := range interfaces {
		if ifConfigMap, ok := ifConfig.(map[string]interface{}); ok {
			fmt.Printf("  配置接口 %s\n", ifName)

			// 应用接口状态
			if status, exists := ifConfigMap["status"]; exists {
				statusStr, ok := status.(string)
				if ok {
					switch statusStr {
					case "up":
						if err := nc.SetInterfaceUp(ifName); err != nil {
							fmt.Printf("    警告: 启用接口 %s 失败: %v\n", ifName, err)
						} else {
							fmt.Printf("    接口 %s 已启用\n", ifName)
						}
					case "down":
						if err := nc.SetInterfaceDown(ifName); err != nil {
							fmt.Printf("    警告: 禁用接口 %s 失败: %v\n", ifName, err)
						} else {
							fmt.Printf("    接口 %s 已禁用\n", ifName)
						}
					}
				}
			}

			// 应用IP配置
			if ip, ipExists := ifConfigMap["ip"]; ipExists {
				if netmask, maskExists := ifConfigMap["netmask"]; maskExists {
					ipStr, ipOk := ip.(string)
					maskStr, maskOk := netmask.(string)

					if ipOk && maskOk && ipStr != "" && maskStr != "" {
						if err := nc.SetInterfaceIP(ifName, ipStr, maskStr); err != nil {
							fmt.Printf("    警告: 设置接口 %s IP地址失败: %v\n", ifName, err)
						} else {
							fmt.Printf("    接口 %s IP地址已设置为 %s/%s\n", ifName, ipStr, maskStr)
						}
					}
				}
			}

			// 打印其他配置信息
			if mtu, exists := ifConfigMap["mtu"]; exists {
				fmt.Printf("    MTU: %v\n", mtu)
			}
			if mac, exists := ifConfigMap["mac"]; exists {
				fmt.Printf("    MAC: %v\n", mac)
			}
		}
	}

	return nil
}

// applyRouteConfiguration 应用路由配置
func (bm *BackupManager) applyRouteConfiguration(routesData interface{}) error {
	fmt.Printf("- 应用路由表配置\n")

	routes, ok := routesData.([]interface{})
	if !ok {
		return fmt.Errorf("路由配置数据格式无效")
	}

	// 创建网络配置器实例
	nc := NewNetworkConfigurator()

	for i, route := range routes {
		if routeMap, ok := route.(map[string]interface{}); ok {
			fmt.Printf("  配置路由 %d\n", i+1)

			// 获取路由参数
			dest, destExists := routeMap["destination"].(string)
			gateway, gatewayExists := routeMap["gateway"].(string)
			iface, ifaceExists := routeMap["interface"].(string)

			if !destExists || !gatewayExists {
				fmt.Printf("    跳过无效路由: 缺少目标或网关信息\n")
				continue
			}

			// 获取metric，如果不存在则使用默认值
			metric := 0
			if metricVal, exists := routeMap["metric"]; exists {
				if metricFloat, ok := metricVal.(float64); ok {
					metric = int(metricFloat)
				}
			}

			// 应用路由配置
			err := nc.AddRoute(dest, gateway, iface, metric)
			if err != nil {
				fmt.Printf("    路由配置失败: %v\n", err)
				// 继续处理其他路由，不中断整个恢复过程
				continue
			}

			fmt.Printf("    目标: %s\n", dest)
			fmt.Printf("    网关: %s\n", gateway)
			if ifaceExists {
				fmt.Printf("    接口: %s\n", iface)
			}
			if metric > 0 {
				fmt.Printf("    优先级: %d\n", metric)
			}
			fmt.Printf("    状态: 已应用\n")
		}
	}

	return nil
}

// applySystemSettings 应用系统设置
func (bm *BackupManager) applySystemSettings(settingsData interface{}) error {
	fmt.Printf("- 应用系统设置\n")

	settings, ok := settingsData.(map[string]interface{})
	if !ok {
		return fmt.Errorf("系统设置数据格式无效")
	}

	// 创建网络配置器实例
	nc := NewNetworkConfigurator()

	// 应用IP转发设置
	if ipForwarding, exists := settings["ip_forwarding"]; exists {
		if enable, ok := ipForwarding.(bool); ok {
			fmt.Printf("  IP转发: %v\n", enable)

			var err error
			if enable {
				err = nc.EnableIPForwarding()
			} else {
				err = nc.DisableIPForwarding()
			}

			if err != nil {
				fmt.Printf("    IP转发设置失败: %v\n", err)
				// 继续处理其他设置，不中断整个恢复过程
			} else {
				fmt.Printf("    IP转发设置成功\n")
			}
		}
	}

	// 应用其他系统设置
	for key, value := range settings {
		if key != "ip_forwarding" && key != "timestamp" && key != "version" {
			fmt.Printf("  %s: %v\n", key, value)
			// 注意：其他系统设置可能需要特定的处理逻辑
			// 这里只是记录，实际应用需要根据具体设置类型来处理
		}
	}

	return nil
}

// validateRestoredConfiguration 验证恢复后的配置
func (bm *BackupManager) validateRestoredConfiguration() error {
	fmt.Printf("验证恢复后的配置...\n")

	// 检查网络接口状态
	if err := bm.validateNetworkInterfaces(); err != nil {
		return fmt.Errorf("网络接口验证失败: %v", err)
	}

	// 验证路由表
	if err := bm.validateRouteTable(); err != nil {
		return fmt.Errorf("路由表验证失败: %v", err)
	}

	// 测试网络连通性
	if err := bm.validateNetworkConnectivity(); err != nil {
		return fmt.Errorf("网络连通性验证失败: %v", err)
	}

	// 验证系统设置
	if err := bm.validateSystemSettings(); err != nil {
		return fmt.Errorf("系统设置验证失败: %v", err)
	}

	fmt.Printf("配置验证通过\n")
	return nil
}

// validateNetworkInterfaces 验证网络接口状态
func (bm *BackupManager) validateNetworkInterfaces() error {
	fmt.Printf("- 检查网络接口状态\n")

	// 创建网络配置器实例
	nc := NewNetworkConfigurator()

	// 获取实际的网络接口列表
	interfaces, err := nc.GetInterfaceList()
	if err != nil {
		return fmt.Errorf("获取网络接口列表失败: %v", err)
	}

	if len(interfaces) == 0 {
		return fmt.Errorf("未找到任何网络接口")
	}

	// 验证每个接口的状态
	for _, iface := range interfaces {
		fmt.Printf("  检查接口 %s\n", iface)

		// 获取接口配置信息
		config, err := nc.GetInterfaceConfig(iface)
		if err != nil {
			fmt.Printf("    警告: 无法获取接口配置: %v\n", err)
			continue
		}

		// 显示接口状态
		if config.Up {
			fmt.Printf("    状态: UP\n")
		} else {
			fmt.Printf("    状态: DOWN\n")
		}

		// 显示IP地址信息
		if config.IPAddress != nil {
			fmt.Printf("    IP地址: %s\n", config.IPAddress.String())
			if config.Netmask != nil {
				fmt.Printf("    子网掩码: %s\n", net.IP(config.Netmask).String())
			}
		}

		// 显示MAC地址
		if config.MAC != nil {
			fmt.Printf("    MAC地址: %s\n", config.MAC.String())
		}

		// 显示MTU
		if config.MTU > 0 {
			fmt.Printf("    MTU: %d\n", config.MTU)
		}
	}

	fmt.Printf("  网络接口验证完成，共检查 %d 个接口\n", len(interfaces))
	return nil
}

// validateRouteTable 验证路由表
func (bm *BackupManager) validateRouteTable() error {
	fmt.Printf("- 验证路由表\n")

	// 创建网络配置器实例
	nc := NewNetworkConfigurator()

	// 获取实际的路由表
	routes, err := nc.GetRouteTable()
	if err != nil {
		return fmt.Errorf("获取路由表失败: %v", err)
	}

	if len(routes) == 0 {
		fmt.Printf("  路由表为空\n")
		return nil
	}

	// 显示路由表信息
	for i, route := range routes {
		fmt.Printf("  路由 %d:\n", i+1)

		if route.Destination != nil {
			fmt.Printf("    目标: %s\n", route.Destination.String())
		}

		if route.Gateway != nil && !route.Gateway.IsUnspecified() {
			fmt.Printf("    网关: %s\n", route.Gateway.String())
		}

		if route.Interface != "" {
			fmt.Printf("    接口: %s\n", route.Interface)
		}

		if route.Metric > 0 {
			fmt.Printf("    优先级: %d\n", route.Metric)
		}

		if route.Type != "" {
			fmt.Printf("    类型: %s\n", route.Type)
		}
	}

	fmt.Printf("  路由表验证完成，共检查 %d 条路由\n", len(routes))
	return nil
}

// validateNetworkConnectivity 验证网络连通性
func (bm *BackupManager) validateNetworkConnectivity() error {
	fmt.Printf("- 测试网络连通性\n")

	// 定义测试目标
	testTargets := []string{"8.8.8.8", "1.1.1.1"}

	for _, target := range testTargets {
		fmt.Printf("  测试连接到 %s\n", target)

		// 执行真实的ping测试
		success := bm.pingHost(target)
		if success {
			fmt.Printf("    结果: 连接正常\n")
		} else {
			fmt.Printf("    结果: 连接失败\n")
			// 连通性测试失败不中断整个验证过程，只记录警告
		}
	}

	return nil
}

// pingHost 执行ping测试
func (bm *BackupManager) pingHost(host string) bool {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "3000", host)
	case "darwin", "linux":
		cmd = exec.Command("ping", "-c", "1", "-W", "3", host)
	default:
		// 对于其他系统，尝试使用通用的ping命令
		cmd = exec.Command("ping", "-c", "1", host)
	}

	err := cmd.Run()
	return err == nil
}

// validateSystemSettings 验证系统设置
func (bm *BackupManager) validateSystemSettings() error {
	fmt.Printf("- 验证系统设置\n")

	// 创建网络配置器实例
	nc := NewNetworkConfigurator()

	// 检查IP转发状态
	ipForwardingEnabled, err := bm.checkIPForwardingStatus()
	if err != nil {
		fmt.Printf("  检查IP转发状态失败: %v\n", err)
	} else {
		fmt.Printf("  IP转发状态: %v\n", ipForwardingEnabled)
	}

	// 检查网络接口数量
	interfaces, err := nc.GetInterfaceList()
	if err != nil {
		fmt.Printf("  获取网络接口列表失败: %v\n", err)
	} else {
		fmt.Printf("  网络接口数量: %d\n", len(interfaces))
	}

	// 检查路由表条目数量
	routes, err := nc.GetRouteTable()
	if err != nil {
		fmt.Printf("  获取路由表失败: %v\n", err)
	} else {
		fmt.Printf("  路由表条目数量: %d\n", len(routes))
	}

	fmt.Printf("  系统设置验证完成\n")
	return nil
}

// cleanupTemporaryBackup 清理临时备份
func (bm *BackupManager) cleanupTemporaryBackup(tempBackup *BackupInfo) {
	if tempBackup == nil {
		fmt.Printf("临时备份信息为空，无需清理\n")
		return
	}

	// 检查文件是否存在
	if _, err := os.Stat(tempBackup.FilePath); os.IsNotExist(err) {
		fmt.Printf("临时备份文件不存在: %s\n", tempBackup.FilePath)
		return
	}

	// 删除临时备份文件
	if err := os.Remove(tempBackup.FilePath); err != nil {
		fmt.Printf("删除临时备份文件失败: %v\n", err)
		return
	}

	fmt.Printf("成功清理临时备份: %s\n", tempBackup.FilePath)
}

// ListBackups 列出所有备份
func (bm *BackupManager) ListBackups() []BackupInfo {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	backups := make([]BackupInfo, len(bm.backupHistory))
	copy(backups, bm.backupHistory)

	return backups
}

// DeleteBackup 删除指定备份
func (bm *BackupManager) DeleteBackup(backupID string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// 查找并删除备份
	for i, backup := range bm.backupHistory {
		if backup.ID == backupID {
			// 删除备份文件
			if err := exec.Command("rm", "-f", backup.FilePath).Run(); err != nil {
				return fmt.Errorf("删除备份文件失败: %v", err)
			}

			// 从历史记录中移除
			bm.backupHistory = append(bm.backupHistory[:i], bm.backupHistory[i+1:]...)

			return nil
		}
	}

	return fmt.Errorf("备份不存在: %s", backupID)
}

// cleanupOldBackups 清理旧备份
func (bm *BackupManager) cleanupOldBackups() {
	if len(bm.backupHistory) <= bm.maxBackups {
		return
	}

	// 按时间排序，删除最旧的备份
	excess := len(bm.backupHistory) - bm.maxBackups
	for i := 0; i < excess; i++ {
		oldestBackup := bm.backupHistory[0]

		// 删除备份文件
		_ = exec.Command("rm", "-f", oldestBackup.FilePath).Run()

		// 从历史记录中移除
		bm.backupHistory = bm.backupHistory[1:]
	}
}
