// 通用JavaScript函数

// API请求辅助函数
async function apiRequest(url, options = {}) {
    const authToken = localStorage.getItem('authToken');
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

// 退出登录
function logout() {
    localStorage.removeItem('authToken');
    window.location.href = '/login';
}

// 格式化字节数
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 显示消息
function showMessage(message, type = 'info') {
    // 创建消息元素
    const messageEl = document.createElement('div');
    messageEl.className = `message message-${type}`;
    messageEl.textContent = message;
    
    // 添加样式
    messageEl.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 5px;
        color: white;
        z-index: 1000;
        max-width: 300px;
    `;
    
    // 根据类型设置背景色
    switch (type) {
        case 'success':
            messageEl.style.backgroundColor = '#27ae60';
            break;
        case 'error':
            messageEl.style.backgroundColor = '#e74c3c';
            break;
        case 'warning':
            messageEl.style.backgroundColor = '#f39c12';
            break;
        default:
            messageEl.style.backgroundColor = '#3498db';
    }
    
    document.body.appendChild(messageEl);
    
    // 3秒后自动移除
    setTimeout(() => {
        if (messageEl.parentNode) {
            messageEl.parentNode.removeChild(messageEl);
        }
    }, 3000);
}

// 确认对话框
function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

// 检查认证状态
function checkAuth() {
    const authToken = localStorage.getItem('authToken');
    if (!authToken && window.location.pathname !== '/login') {
        window.location.href = '/login';
        return false;
    }
    return true;
}

// 页面加载完成后检查认证
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
});