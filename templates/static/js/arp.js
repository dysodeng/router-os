// ARP表管理页面JavaScript

class ARPManager {
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

        // 加载ARP表
        await this.loadARPTable();

        // 设置定时刷新
        setInterval(() => this.loadARPTable(), 5000);

        // 绑定清空ARP表按钮事件
        this.bindClearButton();
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
            row.innerHTML = '<td colspan="4" class="text-center">暂无ARP条目</td>';
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

    bindClearButton() {
        const clearButton = document.getElementById('clearArpBtn');
        if (clearButton) {
            clearButton.addEventListener('click', () => this.clearARPTable());
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
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    window.arpManager = new ARPManager();
});