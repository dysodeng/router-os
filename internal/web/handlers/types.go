package handlers

import (
	"router-os/internal/arp"
	"router-os/internal/dhcp"
	"router-os/internal/firewall"
	"router-os/internal/forwarding"
	"router-os/internal/interfaces"
	"router-os/internal/nat"
	"router-os/internal/netconfig"
	"router-os/internal/port"
	"router-os/internal/qos"
	"router-os/internal/routing"
	"router-os/internal/vpn"
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
