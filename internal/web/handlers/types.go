package handlers

import (
	"router-os/internal/module/arp"
	"router-os/internal/module/dhcp"
	"router-os/internal/module/firewall"
	"router-os/internal/module/forwarding"
	"router-os/internal/module/interfaces"
	"router-os/internal/module/nat"
	"router-os/internal/module/netconfig"
	"router-os/internal/module/port"
	"router-os/internal/module/qos"
	"router-os/internal/module/routing"
	"router-os/internal/module/vpn"
)

// RouterInstance 路由器实例
type RouterInstance struct {
	// InterfaceManager 接口管理器
	InterfaceManager *interfaces.Manager

	// RoutingTable 路由表
	RoutingTable routing.TableInterface

	// ARPTable ARP表
	ARPTable *arp.Table

	// Forwarder 转发器
	Forwarder *forwarding.Engine

	// NetConfig 网络配置
	NetConfig *netconfig.NetworkConfigurator

	// Firewall 防火墙
	Firewall *firewall.Firewall

	// QoS QoS引擎
	QoS *qos.Engine

	// DHCP DHCP服务器
	DHCP *dhcp.Server

	// VPN VPN服务器
	VPN *vpn.VPNServer

	// PortManager 端口管理器
	PortManager *port.Manager

	// NATManager NAT管理器
	NATManager *nat.Manager
}
