// DHCP管理页面JavaScript

class DHCPManager {
    constructor() {
        this.authManager = new AuthManager();
        this.init().then(r => {});
    }

    async init() {
        // 检查认证状态
        if (!this.authManager.checkAuth()) {
            return;
        }

        // 显示页面内容
        document.getElementById('auth-check').style.display = 'none';
        document.getElementById('page-content').style.display = 'block';

        // 加载DHCP数据
        await this.loadDHCPData();

        // 设置定时刷新
        setInterval(() => this.loadDHCPData(), 5000);

        // 绑定事件
        this.bindEvents();
    }

    async loadDHCPData() {
        try {
            // 并行加载配置、租约和保留
            const [config, leases, reservations] = await Promise.all([
                this.loadDHCPConfig(),
                this.loadDHCPLeases(),
            ]);

            this.renderDHCPConfig(config);
            this.renderDHCPLeases(leases);
        } catch (error) {
            console.error('加载DHCP数据出错:', error);
        }
    }

    async loadDHCPConfig() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/dhcp/config');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载DHCP配置出错:', error);
        }
        return {};
    }

    async loadDHCPLeases() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/dhcp/leases');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载DHCP租约出错:', error);
        }
        return {};
    }

    renderDHCPConfig(config) {
        const container = document.getElementById('dhcpConfig');
        if (!container) return;

        container.innerHTML = `
            <div class="config-section">
                <div class="config-grid">
                    <div class="config-item">
                        <label>DHCP状态:</label>
                        <span class="status ${config.enabled ? 'status-enabled' : 'status-disabled'}">
                            ${config.enabled ? '启用' : '禁用'}
                        </span>
                        <button class="btn btn-sm ${config.enabled ? 'btn-warning' : 'btn-success'}" 
                                onclick="dhcpManager.toggleDHCP(${!config.enabled})">
                            ${config.enabled ? '禁用' : '启用'}
                        </button>
                    </div>
                    <div class="config-item">
                        <label>网络接口:</label>
                        <span>${config.interface || 'eth0'}</span>
                        <button class="btn btn-sm btn-primary" onclick="dhcpManager.updateInterface()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>IP地址池:</label>
                        <span>${config.range_start || '192.168.1.100'} - ${config.range_end || '192.168.1.200'}</span>
                        <button class="btn btn-sm btn-primary" onclick="dhcpManager.updateRange()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>子网掩码:</label>
                        <span>${config.netmask || '255.255.255.0'}</span>
                        <button class="btn btn-sm btn-primary" onclick="dhcpManager.updateNetmask()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>网关:</label>
                        <span>${config.gateway || '192.168.1.1'}</span>
                        <button class="btn btn-sm btn-primary" onclick="dhcpManager.updateGateway()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>DNS服务器:</label>
                        <span>${config.dns_servers ? config.dns_servers.join(', ') : '8.8.8.8, 8.8.4.4'}</span>
                        <button class="btn btn-sm btn-primary" onclick="dhcpManager.updateDNS()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>租约时间:</label>
                        <span>${config.lease_time || '24小时'}</span>
                        <button class="btn btn-sm btn-primary" onclick="dhcpManager.updateLeaseTime()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>域名:</label>
                        <span>${config.domain || 'local'}</span>
                        <button class="btn btn-sm btn-primary" onclick="dhcpManager.updateDomain()">
                            修改
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    renderDHCPLeases(data) {
        const container = document.getElementById('dhcpLeases');
        if (!container) return;

        const leases = data.leases || [];

        let leasesHtml = '';
        if (leases.length === 0) {
            leasesHtml = '<tr><td colspan="7" class="text-center">暂无DHCP租约</td></tr>';
        } else {
            leases.forEach(lease => {
                leasesHtml += `
                    <tr>
                        <td>${lease.ip || 'N/A'}</td>
                        <td>${lease.mac || 'N/A'}</td>
                        <td>${lease.hostname || 'N/A'}</td>
                        <td>
                            <span class="status-tag ${lease.status === 'active' ? 'active' : 'expired'}">
                                ${lease.status === 'active' ? '活跃' : '已过期'}
                            </span>
                        </td>
                        <td>${lease.start_time || 'N/A'}</td>
                        <td>${lease.end_time || 'N/A'}</td>
                        <td>
                            <button class="btn btn-sm btn-warning" onclick="dhcpManager.releaseLease('${lease.ip}')">
                                释放
                            </button>
                            <button class="btn btn-sm btn-info" onclick="dhcpManager.renewLease('${lease.ip}')">
                                续租
                            </button>
                        </td>
                    </tr>
                `;
            });
        }

        container.innerHTML = `
            <div class="leases-section">
                <div class="action-buttons">
                    <button class="btn btn-primary" onclick="dhcpManager.showConfigModal()">
                        服务配置
                    </button>
                    <button class="btn btn-secondary" onclick="dhcpManager.clearExpiredLeases()">
                        清理过期租约
                    </button>
                </div>
                <table class="dhcp-table">
                    <thead>
                        <tr>
                            <th>IP地址</th>
                            <th>MAC地址</th>
                            <th>主机名</th>
                            <th>状态</th>
                            <th>开始时间</th>
                            <th>结束时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${leasesHtml}
                    </tbody>
                </table>
            </div>
        `;
    }

    bindEvents() {
        // 弹框关闭事件
        const closeModal = document.getElementById('closeConfigModal');
        if (closeModal) {
            closeModal.addEventListener('click', () => {
                this.hideConfigModal();
            });
        }

        // 点击弹框背景关闭
        const modal = document.getElementById('configModal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.hideConfigModal();
                }
            });
        }
    }

    showConfigModal() {
        const modal = document.getElementById('configModal');
        if (modal) {
            modal.style.display = 'flex';
        }
    }

    hideConfigModal() {
        const modal = document.getElementById('configModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async toggleDHCP(enable) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/dhcp/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    enabled: enable
                })
            });

            if (response.ok) {
                await this.loadDHCPData();
                this.showMessage(`DHCP服务器已${enable ? '启用' : '禁用'}`, 'success');
            } else {
                const error = await response.text();
                this.showMessage(`操作失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('切换DHCP状态出错:', error);
            this.showMessage('操作失败', 'error');
        }
    }

    updateInterface() {
        const iface = prompt('请输入网络接口名称:', 'eth0');
        if (!iface) return;

        this.updateDHCPConfig({ interface: iface });
    }

    updateRange() {
        const rangeStart = prompt('请输入起始IP地址:', '192.168.1.100');
        if (!rangeStart) return;

        const rangeEnd = prompt('请输入结束IP地址:', '192.168.1.200');
        if (!rangeEnd) return;

        this.updateDHCPConfig({ 
            range_start: rangeStart,
            range_end: rangeEnd
        });
    }

    updateNetmask() {
        const netmask = prompt('请输入子网掩码:', '255.255.255.0');
        if (!netmask) return;

        this.updateDHCPConfig({ netmask: netmask });
    }

    updateGateway() {
        const gateway = prompt('请输入网关地址:', '192.168.1.1');
        if (!gateway) return;

        this.updateDHCPConfig({ gateway: gateway });
    }

    updateDNS() {
        const dns = prompt('请输入DNS服务器 (用逗号分隔):', '8.8.8.8, 8.8.4.4');
        if (!dns) return;

        const dnsServers = dns.split(',').map(s => s.trim());
        this.updateDHCPConfig({ dns_servers: dnsServers });
    }

    updateLeaseTime() {
        const leaseTime = prompt('请输入租约时间 (小时):', '24');
        if (!leaseTime) return;

        this.updateDHCPConfig({ lease_time: `${leaseTime}h` });
    }

    updateDomain() {
        const domain = prompt('请输入域名:', 'local');
        if (!domain) return;

        this.updateDHCPConfig({ domain_name: domain });
    }

    async updateDHCPConfig(config) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/dhcp/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(config)
            });

            if (response.ok) {
                await this.loadDHCPData();
                this.showMessage('DHCP配置更新成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`更新失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('更新DHCP配置出错:', error);
            this.showMessage('更新失败', 'error');
        }
    }

    async releaseLease(ip) {
        if (!confirm(`确定要释放IP地址 ${ip} 的租约吗？`)) {
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth('/api/dhcp/leases', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip: ip
                })
            });

            if (response.ok) {
                await this.loadDHCPData();
                this.showMessage('租约释放成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`释放租约失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('释放租约出错:', error);
            this.showMessage('释放租约失败', 'error');
        }
    }

    async renewLease(ip) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/dhcp/leases', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip: ip,
                    action: 'renew'
                })
            });

            if (response.ok) {
                await this.loadDHCPData();
                this.showMessage('租约续租成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`续租失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('续租出错:', error);
            this.showMessage('续租失败', 'error');
        }
    }

    async clearExpiredLeases() {
        if (!confirm('确定要清理所有过期的租约吗？')) {
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth('/api/dhcp/leases/cleanup', {
                method: 'POST'
            });

            if (response.ok) {
                await this.loadDHCPData();
                this.showMessage('过期租约清理成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`清理失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('清理过期租约出错:', error);
            this.showMessage('清理失败', 'error');
        }
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
    window.dhcpManager = new DHCPManager();
});