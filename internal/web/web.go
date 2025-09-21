package web

import (
	"context"
	"fmt"
	"net/http"
	"time"

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

// Server Web管理服务器
type Server struct {
	// server HTTP服务器
	server *http.Server

	// router 路由器实例
	router *RouterInstance

	// running 运行状态
	running bool

	// config 配置
	config Config
}

// Config Web服务器配置
type Config struct {
	// Port 监听端口
	Port int `json:"port"`

	// Host 监听地址
	Host string `json:"host"`

	// Username 管理员用户名
	Username string `json:"username"`

	// Password 管理员密码
	Password string `json:"password"`

	// EnableHTTPS 启用HTTPS
	EnableHTTPS bool `json:"enable_https"`

	// CertFile 证书文件
	CertFile string `json:"cert_file"`

	// KeyFile 私钥文件
	KeyFile string `json:"key_file"`
}

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

// NewWebServer 创建Web服务器
func NewWebServer(config Config, router *RouterInstance) *Server {
	return &Server{
		config: config,
		router: router,
	}
}

// Start 启动Web服务器
func (ws *Server) Start() error {
	// 使用新的模块化路由配置
	mux := ws.setupRoutes()

	addr := fmt.Sprintf("%s:%d", ws.config.Host, ws.config.Port)
	ws.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ws.running = true

	if ws.config.EnableHTTPS {
		return ws.server.ListenAndServeTLS(ws.config.CertFile, ws.config.KeyFile)
	}

	return ws.server.ListenAndServe()
}

// Stop 停止Web服务器
func (ws *Server) Stop() error {
	ws.running = false
	if ws.server != nil {
		// 创建5秒超时的context用于优雅关闭
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// 尝试优雅关闭
		if err := ws.server.Shutdown(ctx); err != nil {
			// 如果优雅关闭失败，强制关闭
			return ws.server.Close()
		}
	}
	return nil
}

// IsRunning 检查服务器是否正在运行
func (ws *Server) IsRunning() bool {
	return ws.running
}
