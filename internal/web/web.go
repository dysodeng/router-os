package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"router-os/internal/arp"
	"router-os/internal/dhcp"
	"router-os/internal/firewall"
	"router-os/internal/forwarding"
	"router-os/internal/interfaces"
	"router-os/internal/netconfig"
	"router-os/internal/qos"
	"router-os/internal/routing"
	"router-os/internal/vpn"
)

// WebServer Web管理服务器
type WebServer struct {
	// server HTTP服务器
	server *http.Server

	// router 路由器实例
	router *RouterInstance

	// running 运行状态
	running bool

	// config 配置
	config WebConfig
}

// WebConfig Web服务器配置
type WebConfig struct {
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
	RoutingTable routing.RoutingTableInterface

	// ARPTable ARP表
	ARPTable *arp.ARPTable

	// Forwarder 转发器
	Forwarder *forwarding.Engine

	// NetConfig 网络配置
	NetConfig *netconfig.NetworkConfigurator

	// Firewall 防火墙
	Firewall *firewall.Firewall

	// QoS QoS引擎
	QoS *qos.QoSEngine

	// DHCP DHCP服务器
	DHCP *dhcp.DHCPServer

	// VPN VPN服务器
	VPN *vpn.VPNServer
}

// NewWebServer 创建Web服务器
func NewWebServer(config WebConfig, router *RouterInstance) *WebServer {
	return &WebServer{
		config: config,
		router: router,
	}
}

// Start 启动Web服务器
func (ws *WebServer) Start() error {
	mux := http.NewServeMux()

	// 静态文件服务
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/static/", ws.handleStatic)

	// API路由
	mux.HandleFunc("/api/login", ws.handleLogin)
	mux.HandleFunc("/api/logout", ws.handleLogout)
	mux.HandleFunc("/api/status", ws.requireAuth(ws.handleStatus))

	// 接口管理API
	mux.HandleFunc("/api/interfaces", ws.requireAuth(ws.handleInterfaces))
	mux.HandleFunc("/api/interfaces/", ws.requireAuth(ws.handleInterfaceDetail))

	// 路由管理API
	mux.HandleFunc("/api/routes", ws.requireAuth(ws.handleRoutes))

	// ARP表API
	mux.HandleFunc("/api/arp", ws.requireAuth(ws.handleARP))

	// 防火墙API
	mux.HandleFunc("/api/firewall/rules", ws.requireAuth(ws.handleFirewallRules))

	// DHCP API
	mux.HandleFunc("/api/dhcp/config", ws.requireAuth(ws.handleDHCPConfig))
	mux.HandleFunc("/api/dhcp/leases", ws.requireAuth(ws.handleDHCPLeases))

	// VPN API
	mux.HandleFunc("/api/vpn/config", ws.requireAuth(ws.handleVPNConfig))
	mux.HandleFunc("/api/vpn/clients", ws.requireAuth(ws.handleVPNClients))

	// QoS API
	mux.HandleFunc("/api/qos/config", ws.requireAuth(ws.handleQoSConfig))

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
func (ws *WebServer) Stop() error {
	ws.running = false
	if ws.server != nil {
		return ws.server.Close()
	}
	return nil
}

// handleIndex 处理首页
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>路由器管理系统</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .nav { display: flex; gap: 20px; margin-top: 20px; }
        .nav-item { background: #34495e; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none; cursor: pointer; }
        .nav-item:hover { background: #4a6741; }
        .content { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card { background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .status-item { text-align: center; }
        .status-value { font-size: 2em; font-weight: bold; color: #27ae60; }
        .status-label { color: #7f8c8d; margin-top: 5px; }
        .table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background: #f8f9fa; font-weight: 600; }
        .btn { background: #3498db; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #2980b9; }
        .btn-danger { background: #e74c3c; }
        .btn-danger:hover { background: #c0392b; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; }
        .form-group input, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .hidden { display: none; }
        .login-form { max-width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 20px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div id="loginForm" class="login-form">
        <h2 style="text-align: center; margin-bottom: 30px;">路由器管理登录</h2>
        <form onsubmit="login(event)">
            <div class="form-group">
                <label>用户名</label>
                <input type="text" id="username" required>
            </div>
            <div class="form-group">
                <label>密码</label>
                <input type="password" id="password" required>
            </div>
            <button type="submit" class="btn" style="width: 100%;">登录</button>
        </form>
    </div>

    <div id="mainApp" class="hidden">
        <div class="container">
            <div class="header">
                <h1>路由器管理系统</h1>
                <div class="nav">
                    <a class="nav-item" onclick="showSection('dashboard')">仪表板</a>
                    <a class="nav-item" onclick="showSection('interfaces')">网络接口</a>
                    <a class="nav-item" onclick="showSection('routes')">路由表</a>
                    <a class="nav-item" onclick="showSection('arp')">ARP表</a>
                    <a class="nav-item" onclick="showSection('firewall')">防火墙</a>
                    <a class="nav-item" onclick="showSection('dhcp')">DHCP</a>
                    <a class="nav-item" onclick="showSection('vpn')">VPN</a>
                    <a class="nav-item" onclick="showSection('qos')">QoS</a>
                    <a class="nav-item" onclick="logout()" style="margin-left: auto;">退出</a>
                </div>
            </div>

            <div id="dashboard" class="content">
                <h2>系统状态</h2>
                <div class="status-grid">
                    <div class="card">
                        <div class="status-item">
                            <div class="status-value" id="interfaceCount">-</div>
                            <div class="status-label">网络接口</div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="status-item">
                            <div class="status-value" id="routeCount">-</div>
                            <div class="status-label">路由条目</div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="status-item">
                            <div class="status-value" id="arpCount">-</div>
                            <div class="status-label">ARP条目</div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="status-item">
                            <div class="status-value" id="dhcpLeases">-</div>
                            <div class="status-label">DHCP租约</div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="interfaces" class="content hidden">
                <h2>网络接口管理</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>接口名称</th>
                            <th>IP地址</th>
                            <th>状态</th>
                            <th>MAC地址</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="interfacesList">
                    </tbody>
                </table>
            </div>

            <div id="routes" class="content hidden">
                <h2>路由表管理</h2>
                <button class="btn" onclick="showAddRouteForm()">添加路由</button>
                <table class="table">
                    <thead>
                        <tr>
                            <th>目标网络</th>
                            <th>网关</th>
                            <th>接口</th>
                            <th>跃点数</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="routesList">
                    </tbody>
                </table>
            </div>

            <div id="arp" class="content hidden">
                <h2>ARP表</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>IP地址</th>
                            <th>MAC地址</th>
                            <th>接口</th>
                            <th>状态</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="arpList">
                    </tbody>
                </table>
            </div>

            <div id="firewall" class="content hidden">
                <h2>防火墙规则</h2>
                <button class="btn" onclick="showAddFirewallRuleForm()">添加规则</button>
                <table class="table">
                    <thead>
                        <tr>
                            <th>动作</th>
                            <th>源地址</th>
                            <th>目标地址</th>
                            <th>端口</th>
                            <th>协议</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="firewallRulesList">
                    </tbody>
                </table>
            </div>

            <div id="dhcp" class="content hidden">
                <h2>DHCP服务器</h2>
                <div class="card">
                    <h3>DHCP配置</h3>
                    <div id="dhcpConfig"></div>
                </div>
                <div class="card">
                    <h3>活动租约</h3>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>IP地址</th>
                                <th>MAC地址</th>
                                <th>主机名</th>
                                <th>租约时间</th>
                                <th>剩余时间</th>
                            </tr>
                        </thead>
                        <tbody id="dhcpLeasesList">
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="vpn" class="content hidden">
                <h2>VPN服务器</h2>
                <div class="card">
                    <h3>VPN配置</h3>
                    <div id="vpnConfig"></div>
                </div>
                <div class="card">
                    <h3>连接的客户端</h3>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>客户端ID</th>
                                <th>IP地址</th>
                                <th>连接时间</th>
                                <th>传输数据</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="vpnClientsList">
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="qos" class="content hidden">
                <h2>QoS流量控制</h2>
                <div class="card">
                    <h3>QoS配置</h3>
                    <div id="qosConfig"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let authToken = '';
        let currentSection = 'dashboard';

        // 登录
        async function login(event) {
            event.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                if (response.ok) {
                    const data = await response.json();
                    authToken = data.token;
                    document.getElementById('loginForm').classList.add('hidden');
                    document.getElementById('mainApp').classList.remove('hidden');
                    loadDashboard();
                } else {
                    alert('登录失败，请检查用户名和密码');
                }
            } catch (error) {
                alert('登录请求失败: ' + error.message);
            }
        }

        // 退出登录
        function logout() {
            authToken = '';
            document.getElementById('mainApp').classList.add('hidden');
            document.getElementById('loginForm').classList.remove('hidden');
        }

        // 显示指定部分
        function showSection(section) {
            document.querySelectorAll('.content').forEach(el => el.classList.add('hidden'));
            document.getElementById(section).classList.remove('hidden');
            currentSection = section;

            switch (section) {
                case 'dashboard':
                    loadDashboard();
                    break;
                case 'interfaces':
                    loadInterfaces();
                    break;
                case 'routes':
                    loadRoutes();
                    break;
                case 'arp':
                    loadARP();
                    break;
                case 'firewall':
                    loadFirewallRules();
                    break;
                case 'dhcp':
                    loadDHCP();
                    break;
                case 'vpn':
                    loadVPN();
                    break;
                case 'qos':
                    loadQoS();
                    break;
            }
        }

        // API请求辅助函数
        async function apiRequest(url, options = {}) {
            const headers = {
                'Authorization': 'Bearer ' + authToken,
                'Content-Type': 'application/json',
                ...options.headers
            };

            const response = await fetch(url, { ...options, headers });
            
            if (response.status === 401) {
                logout();
                return null;
            }

            return response;
        }

        // 加载仪表板
        async function loadDashboard() {
            try {
                const response = await apiRequest('/api/status');
                if (response && response.ok) {
                    const data = await response.json();
                    document.getElementById('interfaceCount').textContent = data.interfaces || 0;
                    document.getElementById('routeCount').textContent = data.routes || 0;
                    document.getElementById('arpCount').textContent = data.arp_entries || 0;
                    document.getElementById('dhcpLeases').textContent = data.dhcp_leases || 0;
                }
            } catch (error) {
                console.error('加载仪表板失败:', error);
            }
        }

        // 加载网络接口
        async function loadInterfaces() {
            try {
                const response = await apiRequest('/api/interfaces');
                if (response && response.ok) {
                    const interfaces = await response.json();
                    const tbody = document.getElementById('interfacesList');
                    tbody.innerHTML = '';

                    interfaces.forEach(iface => {
                        const row = tbody.insertRow();
                        row.innerHTML = 
                            '<td>' + iface.name + '</td>' +
                            '<td>' + (iface.ip || '-') + '</td>' +
                            '<td>' + iface.status + '</td>' +
                            '<td>' + iface.mac + '</td>' +
                            '<td>' +
                                '<button class="btn" onclick="configInterface(\'' + iface.name + '\')">配置</button>' +
                                '<button class="btn ' + (iface.status === 'up' ? 'btn-danger' : '') + '" ' +
                                        'onclick="toggleInterface(\'' + iface.name + '\', \'' + iface.status + '\')">' +
                                    (iface.status === 'up' ? '禁用' : '启用') +
                                '</button>' +
                            '</td>';
                    });
                }
            } catch (error) {
                console.error('加载接口失败:', error);
            }
        }

        // 加载路由表
        async function loadRoutes() {
            try {
                const response = await apiRequest('/api/routes');
                if (response && response.ok) {
                    const routes = await response.json();
                    const tbody = document.getElementById('routesList');
                    tbody.innerHTML = '';

                    routes.forEach(route => {
                        const row = tbody.insertRow();
                        row.innerHTML = 
                            '<td>' + route.destination + '</td>' +
                            '<td>' + route.gateway + '</td>' +
                            '<td>' + route.interface + '</td>' +
                            '<td>' + route.metric + '</td>' +
                            '<td>' +
                                '<button class="btn btn-danger" onclick="deleteRoute(\'' + route.destination + '\')">删除</button>' +
                            '</td>';
                    });
                }
            } catch (error) {
                console.error('加载路由失败:', error);
            }
        }

        // 加载ARP表
        async function loadARP() {
            try {
                const response = await apiRequest('/api/arp');
                if (response && response.ok) {
                    const arpEntries = await response.json();
                    const tbody = document.getElementById('arpList');
                    tbody.innerHTML = '';

                    arpEntries.forEach(entry => {
                        const row = tbody.insertRow();
                        row.innerHTML = 
                            '<td>' + entry.ip + '</td>' +
                            '<td>' + entry.mac + '</td>' +
                            '<td>' + entry.interface + '</td>' +
                            '<td>' + entry.status + '</td>' +
                            '<td>' +
                                '<button class="btn btn-danger" onclick="deleteARPEntry(\'' + entry.ip + '\')">删除</button>' +
                            '</td>';
                    });
                }
            } catch (error) {
                console.error('加载ARP表失败:', error);
            }
        }

        // 加载防火墙规则
        async function loadFirewallRules() {
            try {
                const response = await apiRequest('/api/firewall/rules');
                if (response && response.ok) {
                    const rules = await response.json();
                    const tbody = document.getElementById('firewallRulesList');
                    tbody.innerHTML = '';

                    rules.forEach((rule, index) => {
                        const row = tbody.insertRow();
                        row.innerHTML = 
                            '<td>' + rule.action + '</td>' +
                            '<td>' + (rule.source || 'any') + '</td>' +
                            '<td>' + (rule.destination || 'any') + '</td>' +
                            '<td>' + (rule.port || 'any') + '</td>' +
                            '<td>' + (rule.protocol || 'any') + '</td>' +
                            '<td>' +
                                '<button class="btn btn-danger" onclick="deleteFirewallRule(' + index + ')">删除</button>' +
                            '</td>';
                    });
                }
            } catch (error) {
                console.error('加载防火墙规则失败:', error);
            }
        }

        // 加载DHCP信息
        async function loadDHCP() {
            try {
                const configResponse = await apiRequest('/api/dhcp/config');
                const leasesResponse = await apiRequest('/api/dhcp/leases');

                if (configResponse && configResponse.ok) {
                    const config = await configResponse.json();
                    document.getElementById('dhcpConfig').innerHTML = 
                        '<p><strong>地址池:</strong> ' + config.start_ip + ' - ' + config.end_ip + '</p>' +
                        '<p><strong>子网掩码:</strong> ' + config.subnet_mask + '</p>' +
                        '<p><strong>网关:</strong> ' + config.gateway + '</p>' +
                        '<p><strong>DNS:</strong> ' + config.dns_servers.join(', ') + '</p>' +
                        '<p><strong>租约时间:</strong> ' + config.lease_time + '秒</p>';
                }

                if (leasesResponse && leasesResponse.ok) {
                    const leases = await leasesResponse.json();
                    const tbody = document.getElementById('dhcpLeasesList');
                    tbody.innerHTML = '';

                    leases.forEach(lease => {
                        const row = tbody.insertRow();
                        const remainingTime = Math.max(0, lease.expires - Date.now() / 1000);
                        row.innerHTML = 
                            '<td>' + lease.ip + '</td>' +
                            '<td>' + lease.mac + '</td>' +
                            '<td>' + (lease.hostname || '-') + '</td>' +
                            '<td>' + new Date(lease.start * 1000).toLocaleString() + '</td>' +
                            '<td>' + Math.floor(remainingTime / 60) + '分钟</td>';
                    });
                }
            } catch (error) {
                console.error('加载DHCP信息失败:', error);
            }
        }

        // 加载VPN信息
        async function loadVPN() {
            try {
                const configResponse = await apiRequest('/api/vpn/config');
                const clientsResponse = await apiRequest('/api/vpn/clients');

                if (configResponse && configResponse.ok) {
                    const config = await configResponse.json();
                    document.getElementById('vpnConfig').innerHTML = 
                        '<p><strong>监听端口:</strong> ' + config.port + '</p>' +
                        '<p><strong>协议:</strong> ' + config.protocols.join(', ') + '</p>' +
                        '<p><strong>状态:</strong> ' + (config.running ? '运行中' : '已停止') + '</p>';
                }

                if (clientsResponse && clientsResponse.ok) {
                    const clients = await clientsResponse.json();
                    const tbody = document.getElementById('vpnClientsList');
                    tbody.innerHTML = '';

                    clients.forEach(client => {
                        const row = tbody.insertRow();
                        row.innerHTML = 
                            '<td>' + client.id + '</td>' +
                            '<td>' + client.ip + '</td>' +
                            '<td>' + new Date(client.connected_at * 1000).toLocaleString() + '</td>' +
                            '<td>' + formatBytes(client.bytes_sent) + ' / ' + formatBytes(client.bytes_received) + '</td>' +
                            '<td>' +
                                '<button class="btn btn-danger" onclick="disconnectVPNClient(\'' + client.id + '\')">断开</button>' +
                            '</td>';
                    });
                }
            } catch (error) {
                console.error('加载VPN信息失败:', error);
            }
        }

        // 加载QoS信息
        async function loadQoS() {
            try {
                const response = await apiRequest('/api/qos/config');
                if (response && response.ok) {
                    const config = await response.json();
                    document.getElementById('qosConfig').innerHTML = 
                        '<p><strong>状态:</strong> ' + (config.enabled ? '启用' : '禁用') + '</p>' +
                        '<p><strong>总带宽:</strong> ' + config.total_bandwidth + 'Mbps</p>' +
                        '<p><strong>队列数量:</strong> ' + config.queue_count + '</p>';
                }
            } catch (error) {
                console.error('加载QoS信息失败:', error);
            }
        }

        // 格式化字节数
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // 初始化
        document.addEventListener('DOMContentLoaded', function() {
            // 检查是否已登录
            if (authToken) {
                document.getElementById('loginForm').classList.add('hidden');
                document.getElementById('mainApp').classList.remove('hidden');
                loadDashboard();
            }
        });
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleStatic 处理静态文件
func (ws *WebServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	// 简单的静态文件处理
	http.NotFound(w, r)
}

// handleLogin 处理登录
func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if loginReq.Username == ws.config.Username && loginReq.Password == ws.config.Password {
		token := fmt.Sprintf("token_%d", time.Now().Unix())

		response := map[string]string{
			"token": token,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

// handleLogout 处理退出登录
func (ws *WebServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// requireAuth 认证中间件
func (ws *WebServer) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 简单的token验证
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		handler(w, r)
	}
}

// handleStatus 处理状态查询
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	interfaces := ws.router.InterfaceManager.GetAllInterfaces()
	routes := ws.router.RoutingTable.GetAllRoutes()
	arpEntries := ws.router.ARPTable.GetAllEntries()
	leases := ws.router.DHCP.GetLeases()

	status := map[string]interface{}{
		"interfaces":  len(interfaces),
		"routes":      len(routes),
		"arp_entries": len(arpEntries),
		"dhcp_leases": len(leases),
		"uptime":      time.Since(time.Now()).Seconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleInterfaces 处理接口管理
func (ws *WebServer) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		interfaces := ws.router.InterfaceManager.GetAllInterfaces()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(interfaces)

	case http.MethodPost:
		// 添加接口配置
		var config struct {
			Name string `json:"name"`
			IP   string `json:"ip"`
			Mask string `json:"mask"`
		}

		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// 配置接口IP
		if err := ws.router.NetConfig.SetInterfaceIP(config.Name, config.IP, config.Mask); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInterfaceDetail 处理接口详情
func (ws *WebServer) handleInterfaceDetail(w http.ResponseWriter, r *http.Request) {
	// 从URL路径提取接口名
	path := strings.TrimPrefix(r.URL.Path, "/api/interfaces/")
	interfaceName := strings.Split(path, "/")[0]

	if interfaceName == "" {
		http.Error(w, "Interface name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		iface, err := ws.router.InterfaceManager.GetInterface(interfaceName)
		if err != nil || iface == nil {
			http.Error(w, "Interface not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(iface)

	case http.MethodPut:
		// 更新接口配置
		var config struct {
			IP     string `json:"ip"`
			Mask   string `json:"mask"`
			Enable bool   `json:"enable"`
		}

		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if config.IP != "" {
			mask := config.Mask
			if mask == "" {
				mask = "255.255.255.0" // 默认子网掩码
			}
			if err := ws.router.NetConfig.SetInterfaceIP(interfaceName, config.IP, mask); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if config.Enable {
			ws.router.InterfaceManager.SetInterfaceStatus(interfaceName, interfaces.InterfaceStatusUp)
		} else {
			ws.router.InterfaceManager.SetInterfaceStatus(interfaceName, interfaces.InterfaceStatusDown)
		}

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRoutes 处理路由管理
func (ws *WebServer) handleRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		routes := ws.router.RoutingTable.GetAllRoutes()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(routes)

	case http.MethodPost:
		var route struct {
			Destination string `json:"destination"`
			Gateway     string `json:"gateway"`
			Interface   string `json:"interface"`
			Metric      int    `json:"metric"`
		}

		if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if route.Metric == 0 {
			route.Metric = 1 // 默认度量值
		}

		// 添加路由
		if err := ws.router.NetConfig.AddRoute(route.Destination, route.Gateway, route.Interface, route.Metric); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleARP 处理ARP表
func (ws *WebServer) handleARP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries := ws.router.ARPTable.GetAllEntries()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleFirewallRules 处理防火墙规则
func (ws *WebServer) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules, err := ws.router.Firewall.GetRules("all")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		var rule firewall.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if err := ws.router.Firewall.AddRule("filter", rule); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDHCPConfig 处理DHCP配置
func (ws *WebServer) handleDHCPConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := ws.router.DHCP.GetConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// handleDHCPLeases 处理DHCP租约
func (ws *WebServer) handleDHCPLeases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	leases := ws.router.DHCP.GetLeases()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(leases)
}

// handleVPNConfig 处理VPN配置
func (ws *WebServer) handleVPNConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := ws.router.VPN.GetConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// handleVPNClients 处理VPN客户端
func (ws *WebServer) handleVPNClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clients := ws.router.VPN.GetConnectedClients()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

// handleQoSConfig 处理QoS配置
func (ws *WebServer) handleQoSConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := ws.router.QoS.GetConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}
