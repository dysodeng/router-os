// QoS管理页面JavaScript

class QoSManager {
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

        // 加载QoS配置和规则
        await this.loadQoSData();

        // 设置定时刷新
        setInterval(() => this.loadQoSData(), 5000);

        // 绑定事件
        this.bindEvents();
    }

    async loadQoSData() {
        try {
            // 并行加载配置和规则
            const [config, rules] = await Promise.all([
                this.loadQoSConfig(),
                this.loadQoSRules()
            ]);

            this.renderQoSConfig(config);
            this.renderQoSRules(rules);
        } catch (error) {
            console.error('加载QoS数据出错:', error);
        }
    }

    async loadQoSConfig() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/qos/config');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载QoS配置出错:', error);
        }
        return {};
    }

    async loadQoSRules() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/qos/rules');
            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('加载QoS规则出错:', error);
        }
        return {};
    }

    renderQoSConfig(config) {
        const container = document.getElementById('qosConfig');
        if (!container) return;

        container.innerHTML = `
            <div class="config-section">
                <h4>QoS全局配置</h4>
                <div class="config-grid">
                    <div class="config-item">
                        <label>QoS状态:</label>
                        <span class="status ${config.enabled ? 'status-enabled' : 'status-disabled'}">
                            ${config.enabled ? '启用' : '禁用'}
                        </span>
                        <button class="btn btn-sm ${config.enabled ? 'btn-warning' : 'btn-success'}" 
                                onclick="qosManager.toggleQoS(${!config.enabled})">
                            ${config.enabled ? '禁用' : '启用'}
                        </button>
                    </div>
                    <div class="config-item">
                        <label>总带宽限制:</label>
                        <span>${config.total_bandwidth || 'N/A'}</span>
                        <button class="btn btn-sm btn-primary" onclick="qosManager.updateBandwidth()">
                            修改
                        </button>
                    </div>
                    <div class="config-item">
                        <label>默认队列:</label>
                        <span>${config.default_queue || 'N/A'}</span>
                    </div>
                    <div class="config-item">
                        <label>算法:</label>
                        <span>${config.algorithm || 'N/A'}</span>
                    </div>
                </div>
            </div>
        `;
    }

    renderQoSRules(data) {
        const container = document.getElementById('qosRules');
        if (!container) return;

        const rules = data.rules || [];

        let rulesHtml = '';
        if (rules.length === 0) {
            rulesHtml = '<tr><td colspan="6" class="text-center">暂无QoS规则</td></tr>';
        } else {
            rules.forEach((rule, index) => {
                rulesHtml += `
                    <tr>
                        <td>${rule.id || index + 1}</td>
                        <td>${rule.name || 'N/A'}</td>
                        <td>${rule.source || 'ANY'}</td>
                        <td>${rule.destination || 'ANY'}</td>
                        <td>${rule.bandwidth_limit || 'N/A'}</td>
                        <td>${rule.priority || 'N/A'}</td>
                        <td>
                            <button class="btn btn-sm btn-primary" 
                                    onclick="qosManager.editRule('${rule.id || index}')">
                                编辑
                            </button>
                            <button class="btn btn-sm btn-danger" 
                                    onclick="qosManager.deleteRule('${rule.id || index}')">
                                删除
                            </button>
                        </td>
                    </tr>
                `;
            });
        }

        container.innerHTML = `
            <div class="rules-section">
                <div class="section-header">
                    <h4>QoS规则</h4>
                    <button class="btn btn-success" onclick="qosManager.showAddRuleDialog()">
                        添加规则
                    </button>
                </div>
                <table class="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>规则名称</th>
                            <th>源地址</th>
                            <th>目标地址</th>
                            <th>带宽限制</th>
                            <th>优先级</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rulesHtml}
                    </tbody>
                </table>
            </div>
        `;
    }

    bindEvents() {
        // 这里可以绑定其他事件
    }

    async toggleQoS(enable) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/qos/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    enabled: enable
                })
            });

            if (response.ok) {
                await this.loadQoSData();
                this.showMessage(`QoS已${enable ? '启用' : '禁用'}`, 'success');
            } else {
                const error = await response.text();
                this.showMessage(`操作失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('切换QoS状态出错:', error);
            this.showMessage('操作失败', 'error');
        }
    }

    updateBandwidth() {
        const bandwidth = prompt('请输入总带宽限制 (例如: 100Mbps):');
        if (!bandwidth) return;

        this.updateQoSConfig({ total_bandwidth: bandwidth });
    }

    async updateQoSConfig(config) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/qos/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(config)
            });

            if (response.ok) {
                await this.loadQoSData();
                this.showMessage('QoS配置更新成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`更新失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('更新QoS配置出错:', error);
            this.showMessage('更新失败', 'error');
        }
    }

    showAddRuleDialog() {
        const name = prompt('请输入规则名称:');
        if (!name) return;

        const source = prompt('请输入源地址 (例如: 192.168.1.0/24 或 any):', 'any');
        if (!source) return;

        const destination = prompt('请输入目标地址 (例如: 192.168.1.0/24 或 any):', 'any');
        if (!destination) return;

        const bandwidth = prompt('请输入带宽限制 (例如: 10Mbps):');
        if (!bandwidth) return;

        const priority = prompt('请输入优先级 (1-10, 数字越小优先级越高):', '5');
        if (!priority) return;

        this.addQoSRule(name, source, destination, bandwidth, priority);
    }

    async addQoSRule(name, source, destination, bandwidth, priority) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/qos/rules', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: name,
                    source: source,
                    destination: destination,
                    bandwidth_limit: bandwidth,
                    priority: parseInt(priority) || 5
                })
            });

            if (response.ok) {
                await this.loadQoSData();
                this.showMessage('QoS规则添加成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`添加规则失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('添加QoS规则出错:', error);
            this.showMessage('添加规则失败', 'error');
        }
    }

    editRule(ruleId) {
        // 这里可以实现编辑规则的功能
        this.showMessage('编辑功能待实现', 'info');
    }

    async deleteRule(ruleId) {
        if (!confirm(`确定要删除规则 ${ruleId} 吗？`)) {
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth('/api/qos/rules', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    id: ruleId
                })
            });

            if (response.ok) {
                await this.loadQoSData();
                this.showMessage('QoS规则删除成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`删除规则失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('删除QoS规则出错:', error);
            this.showMessage('删除规则失败', 'error');
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
    window.qosManager = new QoSManager();
});