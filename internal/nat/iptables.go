package nat

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// IptablesManager 基于iptables的NAT管理器
// 实现NAT规则的添加、删除和管理功能
// 使用Linux iptables工具进行网络地址转换配置
type IptablesManager struct {
	// 可以添加配置选项，如是否启用日志等
}

// NewIptablesManager 创建新的iptables NAT管理器
// 返回一个初始化完成的iptables管理器实例
//
// 返回值：
//   - *IptablesManager: iptables管理器实例
//
// 使用示例：
//
//	natManager := NewIptablesManager()
//	err := natManager.EnableIPForwarding()
//	if err != nil {
//	    log.Printf("启用IP转发失败: %v", err)
//	}
func NewIptablesManager() *IptablesManager {
	return &IptablesManager{}
}

// AddMasqueradeRule 添加MASQUERADE规则
// 为指定的WAN接口添加源地址转换规则，允许内网设备通过WAN接口访问外网
//
// 参数：
//   - wanInterface: WAN接口名称（如"ens18"）
//   - lanNetwork: LAN网络地址（如"192.168.1.0/24"）
//
// 返回值：
//   - error: 添加失败时返回错误信息
//
// 执行的iptables命令：
//
//	iptables -t nat -A POSTROUTING -s <lanNetwork> -o <wanInterface> -j MASQUERADE
//
// 使用示例：
//
//	err := natManager.AddMasqueradeRule("ens18", "192.168.1.0/24")
//	if err != nil {
//	    log.Printf("添加MASQUERADE规则失败: %v", err)
//	}
func (im *IptablesManager) AddMasqueradeRule(wanInterface string, lanNetwork string) error {
	// 构建iptables命令
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", lanNetwork, "-o", wanInterface, "-j", "MASQUERADE")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("添加MASQUERADE规则失败: %v, 输出: %s", err, string(output))
	}

	log.Printf("成功添加MASQUERADE规则: %s -> %s", lanNetwork, wanInterface)
	return nil
}

// RemoveMasqueradeRule 移除MASQUERADE规则
// 删除指定WAN接口的源地址转换规则
//
// 参数：
//   - wanInterface: WAN接口名称
//   - lanNetwork: LAN网络地址
//
// 返回值：
//   - error: 删除失败时返回错误信息
//
// 执行的iptables命令：
//
//	iptables -t nat -D POSTROUTING -s <lanNetwork> -o <wanInterface> -j MASQUERADE
func (im *IptablesManager) RemoveMasqueradeRule(wanInterface string, lanNetwork string) error {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", lanNetwork, "-o", wanInterface, "-j", "MASQUERADE")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("移除MASQUERADE规则失败: %v, 输出: %s", err, string(output))
	}

	log.Printf("成功移除MASQUERADE规则: %s -> %s", lanNetwork, wanInterface)
	return nil
}

// AddForwardRule 添加转发规则
// 配置接口间的数据包转发规则，允许数据在指定接口间流动
//
// 参数：
//   - fromInterface: 源接口名称
//   - toInterface: 目标接口名称
//
// 返回值：
//   - error: 添加失败时返回错误信息
//
// 执行的iptables命令：
//
//	iptables -A FORWARD -i <fromInterface> -o <toInterface> -j ACCEPT
//	iptables -A FORWARD -i <toInterface> -o <fromInterface> -m state --state ESTABLISHED,RELATED -j ACCEPT
func (im *IptablesManager) AddForwardRule(fromInterface, toInterface string) error {
	// 添加正向转发规则
	cmd1 := exec.Command("iptables", "-A", "FORWARD",
		"-i", fromInterface, "-o", toInterface, "-j", "ACCEPT")

	output1, err := cmd1.CombinedOutput()
	if err != nil {
		return fmt.Errorf("添加正向转发规则失败: %v, 输出: %s", err, string(output1))
	}

	// 添加反向转发规则（仅允许已建立的连接）
	cmd2 := exec.Command("iptables", "-A", "FORWARD",
		"-i", toInterface, "-o", fromInterface,
		"-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")

	output2, err := cmd2.CombinedOutput()
	if err != nil {
		// 如果第二条规则失败，尝试删除第一条规则
		im.RemoveForwardRule(fromInterface, toInterface)
		return fmt.Errorf("添加反向转发规则失败: %v, 输出: %s", err, string(output2))
	}

	log.Printf("成功添加转发规则: %s <-> %s", fromInterface, toInterface)
	return nil
}

// RemoveForwardRule 移除转发规则
// 删除接口间的数据包转发规则
//
// 参数：
//   - fromInterface: 源接口名称
//   - toInterface: 目标接口名称
//
// 返回值：
//   - error: 删除失败时返回错误信息
func (im *IptablesManager) RemoveForwardRule(fromInterface, toInterface string) error {
	// 移除正向转发规则
	cmd1 := exec.Command("iptables", "-D", "FORWARD",
		"-i", fromInterface, "-o", toInterface, "-j", "ACCEPT")

	output1, err := cmd1.CombinedOutput()
	if err != nil {
		log.Printf("移除正向转发规则失败: %v, 输出: %s", err, string(output1))
	}

	// 移除反向转发规则
	cmd2 := exec.Command("iptables", "-D", "FORWARD",
		"-i", toInterface, "-o", fromInterface,
		"-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")

	output2, err := cmd2.CombinedOutput()
	if err != nil {
		log.Printf("移除反向转发规则失败: %v, 输出: %s", err, string(output2))
	}

	log.Printf("成功移除转发规则: %s <-> %s", fromInterface, toInterface)
	return nil
}

// EnableIPForwarding 启用IP转发
// 在系统级别启用IP数据包转发功能，这是NAT工作的前提条件
//
// 返回值：
//   - error: 启用失败时返回错误信息
//
// 执行的系统命令：
//
//	Linux: echo 1 > /proc/sys/net/ipv4/ip_forward && sysctl -w net.ipv4.ip_forward=1
//	macOS: sysctl -w net.inet.ip.forwarding=1
func (im *IptablesManager) EnableIPForwarding() error {
	// 检查是否为macOS环境
	if _, err := exec.LookPath("pfctl"); err == nil {
		// macOS环境，使用macOS特有的sysctl参数
		cmd := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("macOS IP转发设置失败，但继续运行: %v, 输出: %s", err, string(output))
		} else {
			log.Println("成功启用IP转发 (macOS)")
		}
		return nil
	}

	// Linux环境
	// 临时启用IP转发
	cmd1 := exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	output1, err := cmd1.CombinedOutput()
	if err != nil {
		return fmt.Errorf("临时启用IP转发失败: %v, 输出: %s", err, string(output1))
	}

	// 使用sysctl确保设置生效
	cmd2 := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	output2, err := cmd2.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl设置IP转发失败: %v, 输出: %s", err, string(output2))
	}

	log.Println("成功启用IP转发 (Linux)")
	return nil
}

// DisableIPForwarding 禁用IP转发
// 在系统级别禁用IP数据包转发功能
//
// 返回值：
//   - error: 禁用失败时返回错误信息
func (im *IptablesManager) DisableIPForwarding() error {
	// 检查是否为macOS环境
	if _, err := exec.LookPath("pfctl"); err == nil {
		// macOS环境，使用macOS特有的sysctl参数
		cmd := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=0")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("macOS IP转发禁用失败，但继续运行: %v, 输出: %s", err, string(output))
		} else {
			log.Println("成功禁用IP转发 (macOS)")
		}
		return nil
	}

	// Linux环境
	// 临时禁用IP转发
	cmd1 := exec.Command("sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward")
	output1, err := cmd1.CombinedOutput()
	if err != nil {
		return fmt.Errorf("临时禁用IP转发失败: %v, 输出: %s", err, string(output1))
	}

	// 使用sysctl确保设置生效
	cmd2 := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
	output2, err := cmd2.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl设置IP转发失败: %v, 输出: %s", err, string(output2))
	}

	log.Println("成功禁用IP转发 (Linux)")
	return nil
}

// CheckIPForwarding 检查IP转发状态
// 查询当前系统的IP转发配置状态
//
// 返回值：
//   - bool: true表示已启用，false表示已禁用
//   - error: 查询失败时返回错误信息
func (im *IptablesManager) CheckIPForwarding() (bool, error) {
	cmd := exec.Command("cat", "/proc/sys/net/ipv4/ip_forward")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("检查IP转发状态失败: %v", err)
	}

	status := strings.TrimSpace(string(output))
	return status == "1", nil
}

// ListNATRules 列出当前的NAT规则
// 显示当前系统中所有的NAT转换规则
//
// 返回值：
//   - []string: NAT规则列表
//   - error: 查询失败时返回错误信息
func (im *IptablesManager) ListNATRules() ([]string, error) {
	cmd := exec.Command("iptables", "-t", "nat", "-L", "-n", "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("列出NAT规则失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	var rules []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			rules = append(rules, line)
		}
	}

	return rules, nil
}

// ListForwardRules 列出当前的转发规则
// 显示当前系统中所有的数据包转发规则
//
// 返回值：
//   - []string: 转发规则列表
//   - error: 查询失败时返回错误信息
func (im *IptablesManager) ListForwardRules() ([]string, error) {
	cmd := exec.Command("iptables", "-L", "FORWARD", "-n", "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("列出转发规则失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	var rules []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			rules = append(rules, line)
		}
	}

	return rules, nil
}

// FlushNATRules 清空所有NAT规则
// 删除当前系统中所有的NAT转换规则
//
// 返回值：
//   - error: 清空失败时返回错误信息
//
// 注意：此操作会中断所有现有的NAT连接
func (im *IptablesManager) FlushNATRules() error {
	cmd := exec.Command("iptables", "-t", "nat", "-F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("清空NAT规则失败: %v, 输出: %s", err, string(output))
	}

	log.Println("成功清空所有NAT规则")
	return nil
}

// FlushForwardRules 清空所有转发规则
// 删除当前系统中所有的数据包转发规则
//
// 返回值：
//   - error: 清空失败时返回错误信息
//
// 注意：此操作会阻止所有接口间的数据包转发
func (im *IptablesManager) FlushForwardRules() error {
	cmd := exec.Command("iptables", "-F", "FORWARD")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("清空转发规则失败: %v, 输出: %s", err, string(output))
	}

	log.Println("成功清空所有转发规则")
	return nil
}
