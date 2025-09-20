// 防火墙管理页面JavaScript

class FirewallManager {
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

        // 加载防火墙规则
        await this.loadFirewallRules();

        // 设置定时刷新
        setInterval(() => this.loadFirewallRules(), 5000);

        // 绑定添加规则按钮事件
        this.bindAddRuleButton();
    }

    async loadFirewallRules() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/firewall/rules');
            if (response.ok) {
                const data = await response.json();
                this.renderFirewallRules(data.rules || []);
            } else {
                console.error('加载防火墙规则失败:', response.status);
            }
        } catch (error) {
            console.error('加载防火墙规则出错:', error);
        }
    }

    renderFirewallRules(rules) {
        const tbody = document.getElementById('firewallRulesList');
        tbody.innerHTML = '';

        if (rules.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="7" class="text-center">暂无防火墙规则</td>';
            tbody.appendChild(row);
            return;
        }

        rules.forEach((rule, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${rule.id || index + 1}</td>
                <td>
                    <span class="action ${rule.action === 'ACCEPT' ? 'action-accept' : 'action-drop'}">
                        ${rule.action === 'ACCEPT' ? '允许' : '拒绝'}
                    </span>
                </td>
                <td>${rule.protocol || 'ALL'}</td>
                <td>${rule.source || 'ANY'}</td>
                <td>${rule.destination || 'ANY'}</td>
                <td>${rule.port || 'ANY'}</td>
                <td>
                    <button class="btn btn-sm btn-danger" 
                            onclick="firewallManager.deleteRule('${rule.id || index}')">
                        删除
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    bindAddRuleButton() {
        const addButton = document.getElementById('addRuleBtn');
        if (addButton) {
            addButton.addEventListener('click', () => this.showAddRuleDialog());
        }
    }

    showAddRuleDialog() {
        const action = prompt('请选择动作 (ACCEPT/DROP):', 'ACCEPT');
        if (!action || !['ACCEPT', 'DROP'].includes(action.toUpperCase())) {
            this.showMessage('动作必须是 ACCEPT 或 DROP', 'error');
            return;
        }

        const protocol = prompt('请输入协议 (tcp/udp/icmp/all):', 'tcp');
        if (!protocol) return;

        const source = prompt('请输入源地址 (例如: 192.168.1.0/24 或 any):', 'any');
        if (!source) return;

        const destination = prompt('请输入目标地址 (例如: 192.168.1.0/24 或 any):', 'any');
        if (!destination) return;

        const port = prompt('请输入端口 (例如: 80 或 80-90 或 any):', 'any');
        if (!port) return;

        this.addRule(action.toUpperCase(), protocol, source, destination, port);
    }

    async addRule(action, protocol, source, destination, port) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/firewall/rules/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: action,
                    protocol: protocol,
                    source: source,
                    destination: destination,
                    port: port
                })
            });

            if (response.ok) {
                await this.loadFirewallRules();
                this.showMessage('防火墙规则添加成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`添加规则失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('添加防火墙规则出错:', error);
            this.showMessage('添加规则失败', 'error');
        }
    }

    async deleteRule(ruleId) {
        if (!confirm(`确定要删除规则 ${ruleId} 吗？`)) {
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth('/api/firewall/rules/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    id: ruleId
                })
            });

            if (response.ok) {
                await this.loadFirewallRules();
                this.showMessage('防火墙规则删除成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`删除规则失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('删除防火墙规则出错:', error);
            this.showMessage('删除规则失败', 'error');
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
    window.firewallManager = new FirewallManager();
});