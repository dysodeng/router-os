// ARP表管理页面JavaScript

class ARPManager {
    constructor() {
        this.authManager = new AuthManager();
        this.refreshTimer = null;
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

        // 加载ARP表
        await this.loadARPTable();

        // 设置定时刷新
        this.startAutoRefresh();

        // 绑定所有按钮事件
        this.bindButtons();
    }

    startAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
        }
        this.refreshTimer = setInterval(() => this.loadARPTable(), 5000);
    }

    stopAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }

    async loadARPTable() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/arp');
            if (response.ok) {
                const data = await response.json();
                this.renderARPTable(data.entries || []);
            } else {
                console.error('加载ARP表失败:', response.status);
            }
        } catch (error) {
            console.error('加载ARP表出错:', error);
        }
    }

    renderARPTable(entries) {
        const tbody = document.getElementById('arpList');
        tbody.innerHTML = '';

        if (entries.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="5" class="text-center">暂无ARP条目</td>';
            tbody.appendChild(row);
            return;
        }

        entries.forEach(entry => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${entry.ip || 'N/A'}</td>
                <td>${entry.mac || 'N/A'}</td>
                <td>${entry.interface || 'N/A'}</td>
                <td>
                    <span class="status ${entry.status === 'reachable' ? 'status-up' : 'status-down'}">
                        ${this.getStatusText(entry.status)}
                    </span>
                </td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="arpManager.deleteEntry('${entry.ip}')">删除</button>
                    <button class="btn btn-sm btn-info" onclick="arpManager.resolveIP('${entry.ip}')">解析</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    getStatusText(status) {
        switch (status) {
            case 'reachable':
                return '可达';
            case 'stale':
                return '过期';
            case 'incomplete':
                return '不完整';
            case 'permanent':
                return '永久';
            default:
                return status || '未知';
        }
    }

    bindButtons() {
        // 刷新按钮
        const refreshBtn = document.getElementById('refreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadARPTable());
        }

        // 清空按钮
        const clearBtn = document.getElementById('clearBtn');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearARPTable());
        }

        // 添加静态条目按钮
        const addStaticBtn = document.getElementById('addStaticBtn');
        if (addStaticBtn) {
            addStaticBtn.addEventListener('click', () => this.showAddStaticForm());
        }

        // 确认添加按钮
        const confirmAddBtn = document.getElementById('confirmAddBtn');
        if (confirmAddBtn) {
            confirmAddBtn.addEventListener('click', () => this.addStaticEntry());
        }

        // 取消添加按钮
        const cancelAddBtn = document.getElementById('cancelAddBtn');
        if (cancelAddBtn) {
            cancelAddBtn.addEventListener('click', () => this.hideAddStaticForm());
        }

        // 导出按钮
        const exportBtn = document.getElementById('exportBtn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportARPTable());
        }

        // 统计信息按钮
        const statsBtn = document.getElementById('statsBtn');
        if (statsBtn) {
            statsBtn.addEventListener('click', () => this.toggleStats());
        }
    }

    async clearARPTable() {
        if (!confirm('确定要清空ARP表吗？这将删除所有ARP条目。')) {
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth('/api/arp/clear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (response.ok) {
                await this.loadARPTable();
                this.showMessage('ARP表已清空', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`清空ARP表失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('清空ARP表出错:', error);
            this.showMessage('清空ARP表失败', 'error');
        }
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

    // 显示添加静态条目表单
    showAddStaticForm() {
        document.getElementById('addStaticForm').style.display = 'block';
    }

    // 隐藏添加静态条目表单
    hideAddStaticForm() {
        document.getElementById('addStaticForm').style.display = 'none';
        // 清空表单
        document.getElementById('staticIP').value = '';
        document.getElementById('staticMAC').value = '';
        document.getElementById('staticInterface').value = '';
    }

    // 添加静态ARP条目
    async addStaticEntry() {
        const ip = document.getElementById('staticIP').value.trim();
        const mac = document.getElementById('staticMAC').value.trim();
        const iface = document.getElementById('staticInterface').value.trim();

        if (!ip || !mac || !iface) {
            this.showMessage('请填写所有字段', 'error');
            return;
        }

        // 验证IP格式
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            this.showMessage('IP地址格式不正确', 'error');
            return;
        }

        // 验证MAC格式
        const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        if (!macRegex.test(mac)) {
            this.showMessage('MAC地址格式不正确', 'error');
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth('/api/arp/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip: ip,
                    mac: mac,
                    interface: iface
                })
            });

            if (response.ok) {
                this.hideAddStaticForm();
                await this.loadARPTable();
                this.showMessage('静态ARP条目添加成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`添加失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('添加静态ARP条目出错:', error);
            this.showMessage('添加失败', 'error');
        }
    }

    // 删除ARP条目
    async deleteEntry(ip) {
        if (!confirm(`确定要删除IP ${ip} 的ARP条目吗？`)) {
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth(`/api/arp/delete/${ip}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                await this.loadARPTable();
                this.showMessage('ARP条目删除成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`删除失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('删除ARP条目出错:', error);
            this.showMessage('删除失败', 'error');
        }
    }

    // 解析IP地址
    async resolveIP(ip) {
        try {
            // 暂停自动刷新以避免冲突
            this.stopAutoRefresh();
            
            this.showMessage(`正在解析 ${ip}...`, 'info');
            
            const response = await this.authManager.fetchWithAuth('/api/arp/resolve', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ ip: ip })
            });

            if (response.ok) {
                this.showMessage(`ARP解析请求已发送，正在解析 ${ip}...`, 'success');
                // 延迟刷新以显示解析结果
                setTimeout(() => {
                    this.loadARPTable();
                    // 恢复自动刷新
                    this.startAutoRefresh();
                }, 3000);
            } else {
                const error = await response.text();
                this.showMessage(`解析失败: ${error}`, 'error');
                // 恢复自动刷新
                this.startAutoRefresh();
            }
        } catch (error) {
            console.error('解析IP出错:', error);
            this.showMessage(`解析失败: ${error.message}`, 'error');
            // 恢复自动刷新
            this.startAutoRefresh();
        }
    }

    // 导出ARP表
    async exportARPTable() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/arp');
            if (response.ok) {
                const data = await response.json();
                const entries = data.entries || [];
                
                // 生成CSV内容
                let csvContent = 'IP地址,MAC地址,接口,状态\n';
                entries.forEach(entry => {
                    csvContent += `${entry.ip || ''},${entry.mac || ''},${entry.interface || ''},${this.getStatusText(entry.status)}\n`;
                });

                // 创建下载链接
                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                const link = document.createElement('a');
                const url = URL.createObjectURL(blob);
                link.setAttribute('href', url);
                link.setAttribute('download', `arp_table_${new Date().toISOString().slice(0, 10)}.csv`);
                link.style.visibility = 'hidden';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);

                this.showMessage('ARP表导出成功', 'success');
            } else {
                this.showMessage('导出失败', 'error');
            }
        } catch (error) {
            console.error('导出ARP表出错:', error);
            this.showMessage('导出失败', 'error');
        }
    }

    // 切换统计信息显示
    async toggleStats() {
        const statsDiv = document.getElementById('statsInfo');
        if (statsDiv.style.display === 'none') {
            await this.loadStats();
            statsDiv.style.display = 'block';
        } else {
            statsDiv.style.display = 'none';
        }
    }

    // 加载统计信息
    async loadStats() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/arp/stats');
            if (response.ok) {
                const stats = await response.json();
                const statsContent = document.getElementById('statsContent');
                statsContent.innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                        <div><strong>总条目数:</strong> ${stats.total_entries || 0}</div>
                        <div><strong>可达条目:</strong> ${stats.reachable_entries || 0}</div>
                        <div><strong>过期条目:</strong> ${stats.stale_entries || 0}</div>
                        <div><strong>不完整条目:</strong> ${stats.incomplete_entries || 0}</div>
                        <div><strong>永久条目:</strong> ${stats.permanent_entries || 0}</div>
                        <div><strong>最大容量:</strong> ${stats.max_entries || 0}</div>
                    </div>
                `;
            } else {
                this.showMessage('加载统计信息失败', 'error');
            }
        } catch (error) {
            console.error('加载统计信息出错:', error);
            this.showMessage('加载统计信息失败', 'error');
        }
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    window.arpManager = new ARPManager();
});