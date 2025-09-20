// 系统监控页面JavaScript

class MonitorManager {
    constructor() {
        this.authManager = new AuthManager();
        this.charts = {};
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

        // 加载监控数据
        await this.loadMonitorData();

        // 设置定时刷新
        setInterval(() => this.loadMonitorData(), 5000);
    }

    async loadMonitorData() {
        try {
            // 并行加载所有监控数据
            const [systemStats, networkStats, firewallStats, routingStats] = await Promise.all([
                this.loadSystemStats(),
                this.loadNetworkStats(),
                this.loadFirewallStats(),
                this.loadRoutingStats()
            ]);

            this.renderSystemStats(systemStats);
            this.renderNetworkStats(networkStats);
            this.renderFirewallStats(firewallStats);
            this.renderRoutingStats(routingStats);
        } catch (error) {
            console.error('加载监控数据出错:', error);
        }
    }

    async loadSystemStats() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/monitor/system');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载系统统计出错:', error);
        }
        return {};
    }

    async loadNetworkStats() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/monitor/network');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载网络统计出错:', error);
        }
        return {};
    }

    async loadFirewallStats() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/monitor/firewall');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载防火墙统计出错:', error);
        }
        return {};
    }

    async loadRoutingStats() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/monitor/routing');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载路由统计出错:', error);
        }
        return {};
    }

    renderSystemStats(stats) {
        const container = document.getElementById('systemStats');
        if (!container) return;

        container.innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <h4>CPU使用率</h4>
                    <div class="stat-value">${stats.cpu_usage || '0'}%</div>
                    <div class="progress">
                        <div class="progress-bar" style="width: ${stats.cpu_usage || 0}%"></div>
                    </div>
                </div>
                <div class="stat-card">
                    <h4>内存使用率</h4>
                    <div class="stat-value">${stats.memory_usage || '0'}%</div>
                    <div class="progress">
                        <div class="progress-bar" style="width: ${stats.memory_usage || 0}%"></div>
                    </div>
                </div>
                <div class="stat-card">
                    <h4>磁盘使用率</h4>
                    <div class="stat-value">${stats.disk_usage || '0'}%</div>
                    <div class="progress">
                        <div class="progress-bar" style="width: ${stats.disk_usage || 0}%"></div>
                    </div>
                </div>
                <div class="stat-card">
                    <h4>系统负载</h4>
                    <div class="stat-value">${stats.load_average || '0.00'}</div>
                </div>
                <div class="stat-card">
                    <h4>运行时间</h4>
                    <div class="stat-value">${stats.uptime || '0天'}</div>
                </div>
                <div class="stat-card">
                    <h4>进程数</h4>
                    <div class="stat-value">${stats.process_count || '0'}</div>
                </div>
            </div>
        `;
    }

    renderNetworkStats(stats) {
        const container = document.getElementById('networkStats');
        if (!container) return;

        const interfaces = stats.interfaces || [];
        let interfaceHtml = '';

        interfaces.forEach(iface => {
            interfaceHtml += `
                <div class="interface-card">
                    <h5>${iface.name}</h5>
                    <div class="interface-stats">
                        <div class="stat-item">
                            <span>接收: ${this.formatBytes(iface.rx_bytes || 0)}</span>
                            <span>发送: ${this.formatBytes(iface.tx_bytes || 0)}</span>
                        </div>
                        <div class="stat-item">
                            <span>接收包: ${iface.rx_packets || 0}</span>
                            <span>发送包: ${iface.tx_packets || 0}</span>
                        </div>
                        <div class="stat-item">
                            <span>错误: ${iface.rx_errors || 0}</span>
                            <span>丢包: ${iface.tx_drops || 0}</span>
                        </div>
                    </div>
                </div>
            `;
        });

        container.innerHTML = `
            <div class="network-overview">
                <div class="stat-card">
                    <h4>总流量</h4>
                    <div class="stat-value">${this.formatBytes(stats.total_bytes || 0)}</div>
                </div>
                <div class="stat-card">
                    <h4>活跃连接</h4>
                    <div class="stat-value">${stats.active_connections || 0}</div>
                </div>
            </div>
            <div class="interfaces-stats">
                ${interfaceHtml}
            </div>
        `;
    }

    renderFirewallStats(stats) {
        const container = document.getElementById('firewallStats');
        if (!container) return;

        container.innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <h4>规则数量</h4>
                    <div class="stat-value">${stats.rules_count || 0}</div>
                </div>
                <div class="stat-card">
                    <h4>允许包数</h4>
                    <div class="stat-value">${stats.accepted_packets || 0}</div>
                </div>
                <div class="stat-card">
                    <h4>拒绝包数</h4>
                    <div class="stat-value">${stats.dropped_packets || 0}</div>
                </div>
                <div class="stat-card">
                    <h4>阻止率</h4>
                    <div class="stat-value">${stats.block_rate || '0'}%</div>
                </div>
            </div>
        `;
    }

    renderRoutingStats(stats) {
        const container = document.getElementById('routingStats');
        if (!container) return;

        container.innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <h4>路由条目</h4>
                    <div class="stat-value">${stats.routes_count || 0}</div>
                </div>
                <div class="stat-card">
                    <h4>转发包数</h4>
                    <div class="stat-value">${stats.forwarded_packets || 0}</div>
                </div>
                <div class="stat-card">
                    <h4>路由缓存命中率</h4>
                    <div class="stat-value">${stats.cache_hit_rate || '0'}%</div>
                </div>
                <div class="stat-card">
                    <h4>ARP条目</h4>
                    <div class="stat-value">${stats.arp_entries || 0}</div>
                </div>
            </div>
        `;
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
        messageDiv.className = `alert alert-${type === 'success' ? 'success' : 'danger'}`;
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
    window.monitorManager = new MonitorManager();
});