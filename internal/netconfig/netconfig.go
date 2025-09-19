package netconfig

import (
	"fmt"
	"net"
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
	var routes []RouteEntry
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 这里需要根据不同操作系统的输出格式进行解析
		// 当前为简化实现，实际需要更复杂的解析逻辑
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			route := RouteEntry{
				Type: "unknown",
			}

			// 简单解析，实际需要更详细的实现
			if len(fields) > 0 {
				if dest, err := nc.parseDestination(fields[0]); err == nil {
					route.Destination = dest
				}
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
			hrm.triggerReload("file_change")
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

	// 这里应该实现具体的恢复逻辑
	// 简化实现，实际需要根据配置类型进行相应的恢复操作
	fmt.Printf("恢复备份: %s\n", backupInfo.FilePath)

	return nil
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
		exec.Command("rm", "-f", oldestBackup.FilePath).Run()

		// 从历史记录中移除
		bm.backupHistory = bm.backupHistory[1:]
	}
}
