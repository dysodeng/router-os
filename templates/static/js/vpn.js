// VPN管理页面JavaScript

class VPNManager {
    constructor() {
        this.authManager = new AuthManager();
        this.init();
    }

    async init() {
        // 检查认证状态
        if (!await this.authManager.checkAuth()) {
            return;
        }

        // 显示页面内容
        document.getElementById('auth-check').style.display = 'none';
        document.getElementById('page-content').style.display = 'block';

        // 加载VPN数据
        await this.loadVPNData();

        // 设置定时刷新
        setInterval(() => this.loadVPNData(), 5000);

        // 绑定事件
        this.bindEvents();
    }

    async loadVPNData() {
        try {
            // 并行加载配置和客户端
            const [config, clients] = await Promise.all([
                this.loadVPNConfig(),
                this.loadVPNClients()
            ]);

            this.renderVPNConfig(config);
            this.renderVPNClients(clients);
        } catch (error) {
            console.error('加载VPN数据出错:', error);
        }
    }

    async loadVPNConfig() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/vpn/config');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载VPN配置出错:', error);
        }
        return {};
    }

    async loadVPNClients() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/vpn/clients');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载VPN客户端出错:', error);
        }
        return {};
    }

    renderVPNConfig(config) {
        const container = document.getElementById('vpnConfig');
        if (!container) return;

        container.innerHTML = `
            <div class="config-section">
                <h4>VPN服务器配置</h4>
                <div class="config-grid">
                    <div class="config-item">
                        <label>VPN状态:</label>
                        <span class="status ${config.enabled ? 'status-enabled' : 'status-disabled'}">
                            ${config.enabled ? '启用' : '禁用'}
                        </span>
                        <button class="btn btn-sm ${config.enabled ? 'btn-warning' : 'btn-success'}" 
                                onclick="vpnManager.toggleVPN(${!config.enabled})">
                            ${config.enabled ? '禁用' : '启用'}
                        </button>
                    </div>
                    <div class="config-item">
                        <label>VPN类型:</label>
                        <span>${config.type || 'OpenVPN'}</span>
                    </div>
                    <div class="config-item">
                        <label>监听端口:</label>
                        <span>${config.port || '1194'}</span>
                        <button class="btn btn-sm btn-primary" onclick="vpnManager.updatePort()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>协议:</label>
                        <span>${config.protocol || 'UDP'}</span>
                    </div>
                    <div class="config-item">
                        <label>网络地址:</label>
                        <span>${config.network || '10.8.0.0/24'}</span>
                        <button class="btn btn-sm btn-primary" onclick="vpnManager.updateNetwork()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>DNS服务器:</label>
                        <span>${config.dns || '8.8.8.8'}</span>
                        <button class="btn btn-sm btn-primary" onclick="vpnManager.updateDNS()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>最大客户端:</label>
                        <span>${config.max_clients || '100'}</span>
                    </div>
                    <div class="config-item">
                        <label>加密算法:</label>
                        <span>${config.cipher || 'AES-256-CBC'}</span>
                    </div>
                </div>
            </div>
        `;
    }

    renderVPNClients(data) {
        const container = document.getElementById('vpnClients');
        if (!container) return;

        const clients = data.clients || [];

        let clientsHtml = '';
        if (clients.length === 0) {
            clientsHtml = '<tr><td colspan="6" class="text-center">暂无VPN客户端</td></tr>';
        } else {
            clients.forEach((client, index) => {
                clientsHtml += `
                    <tr>
                        <td>${client.name || `Client-${index + 1}`}</td>
                        <td>${client.virtual_ip || 'N/A'}</td>
                        <td>${client.real_ip || 'N/A'}</td>
                        <td>
                            <span class="status ${client.status === 'connected' ? 'status-connected' : 'status-disconnected'}">
                                ${client.status === 'connected' ? '已连接' : '未连接'}
                            </span>
                        </td>
                        <td>${client.connected_since || 'N/A'}</td>
                        <td>${this.formatBytes(client.bytes_received || 0)} / ${this.formatBytes(client.bytes_sent || 0)}</td>
                        <td>
                            ${client.status === 'connected' ? 
                                `<button class="btn btn-sm btn-warning" onclick="vpnManager.disconnectClient('${client.name}')">断开</button>` :
                                `<button class="btn btn-sm btn-danger" onclick="vpnManager.deleteClient('${client.name}')">删除</button>`
                            }
                            <button class="btn btn-sm btn-info" onclick="vpnManager.downloadConfig('${client.name}')">下载配置</button>
                        </td>
                    </tr>
                `;
            });
        }

        container.innerHTML = `
            <div class="clients-section">
                <div class="section-header">
                    <h4>VPN客户端</h4>
                    <button class="btn btn-success" onclick="vpnManager.showAddClientDialog()">
                        添加客户端
                    </button>
                </div>
                <table class="table">
                    <thead>
                        <tr>
                            <th>客户端名称</th>
                            <th>虚拟IP</th>
                            <th>真实IP</th>
                            <th>状态</th>
                            <th>连接时间</th>
                            <th>流量 (接收/发送)</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${clientsHtml}
                    </tbody>
                </table>
            </div>
        `;
    }

    bindEvents() {
        // 这里可以绑定其他事件
    }

    async toggleVPN(enable) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/vpn/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    enabled: enable
                })
            });

            if (response.ok) {
                await this.loadVPNData();
                this.showMessage(`VPN服务器已${enable ? '启用' : '禁用'}`, 'success');
            } else {
                const error = await response.text();
                this.showMessage(`操作失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('切换VPN状态出错:', error);
            this.showMessage('操作失败', 'error');
        }
    }

    updatePort() {
        const port = prompt('请输入VPN监听端口:', '1194');
        if (!port) return;

        this.updateVPNConfig({ port: parseInt(port) });
    }

    updateNetwork() {
        const network = prompt('请输入VPN网络地址 (例如: 10.8.0.0/24):', '10.8.0.0/24');
        if (!network) return;

        this.updateVPNConfig({ network: network });
    }

    updateDNS() {
        const dns = prompt('请输入DNS服务器地址:', '8.8.8.8');
        if (!dns) return;

        this.updateVPNConfig({ dns: dns });
    }

    async updateVPNConfig(config) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/vpn/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(config)
            });

            if (response.ok) {
                await this.loadVPNData();
                this.showMessage('VPN配置更新成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`更新失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('更新VPN配置出错:', error);
            this.showMessage('更新失败', 'error');
        }
    }

    showAddClientDialog() {
        const name = prompt('请输入客户端名称:');
        if (!name) return;

        this.addVPNClient(name);
    }

    async addVPNClient(name) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/vpn/clients', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: name
                })
            });

            if (response.ok) {
                await this.loadVPNData();
                this.showMessage('VPN客户端添加成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`添加客户端失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('添加VPN客户端出错:', error);
            this.showMessage('添加客户端失败', 'error');
        }
    }

    async disconnectClient(clientName) {
        if (!confirm(`确定要断开客户端 ${clientName} 的连接吗？`)) {
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth('/api/vpn/clients', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: clientName,
                    action: 'disconnect'
                })
            });

            if (response.ok) {
                await this.loadVPNData();
                this.showMessage('客户端连接已断开', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`断开连接失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('断开VPN客户端出错:', error);
            this.showMessage('断开连接失败', 'error');
        }
    }

    async deleteClient(clientName) {
        if (!confirm(`确定要删除客户端 ${clientName} 吗？`)) {
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth('/api/vpn/clients', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: clientName
                })
            });

            if (response.ok) {
                await this.loadVPNData();
                this.showMessage('VPN客户端删除成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`删除客户端失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('删除VPN客户端出错:', error);
            this.showMessage('删除客户端失败', 'error');
        }
    }

    downloadConfig(clientName) {
        // 创建下载链接
        const downloadUrl = `/api/vpn/clients/${clientName}/config`;
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = `${clientName}.ovpn`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        this.showMessage(`正在下载 ${clientName} 的配置文件`, 'info');
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    showMessage(message, type) {
        // 创建消息提示
        const messageDiv = document.createElement('div');
        messageDiv.className = `alert alert-${type === 'success' ? 'success' : type === 'info' ? 'info' : 'danger'}`;
        messageDiv.textContent = message;
        messageDiv.style.position = 'fixed';
        messageDiv.style.top = '20px';
        messageDiv.style.right = '20px';
        messageDiv.style.zIndex = '9999';

        document.body.appendChild(messageDiv);

        // 3秒后自动移除
        setTimeout(() => {
            if (messageDiv.parentNode) {
                messageDiv.parentNode.removeChild(messageDiv);
            }
        }, 3000);
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    window.vpnManager = new VPNManager();
});