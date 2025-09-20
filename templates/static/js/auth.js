// 通用认证检查和401错误处理
class AuthManager {
    constructor() {
        this.token = localStorage.getItem('authToken');
        this.checkAuth();
    }

    // 检查认证状态
    checkAuth() {
        if (!this.token) {
            this.redirectToLogin();
            return false;
        }
        return true;
    }

    // 跳转到登录页面
    redirectToLogin() {
        window.location.href = '/login';
    }

    // 获取认证头部
    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json'
        };
    }

    // 发送认证请求
    async fetchWithAuth(url, options = {}) {
        if (!this.checkAuth()) {
            return null;
        }

        const headers = {
            ...this.getAuthHeaders(),
            ...(options.headers || {})
        };

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            // 处理401错误
            if (response.status === 401) {
                console.log('认证失败，跳转到登录页面');
                localStorage.removeItem('authToken');
                this.redirectToLogin();
                return null;
            }

            return response;
        } catch (error) {
            console.error('请求失败:', error);
            throw error;
        }
    }

    // 显示认证检查提示
    showAuthCheck() {
        const authCheckDiv = document.getElementById('auth-check');
        if (authCheckDiv) {
            authCheckDiv.style.display = 'block';
        }
    }

    // 隐藏认证检查提示
    hideAuthCheck() {
        const authCheckDiv = document.getElementById('auth-check');
        if (authCheckDiv) {
            authCheckDiv.style.display = 'none';
        }
    }

    // 显示未认证提示
    showUnauthorized() {
        const unauthorizedDiv = document.getElementById('unauthorized');
        if (unauthorizedDiv) {
            unauthorizedDiv.style.display = 'block';
        }
    }

    // 显示页面内容
    showContent() {
        const contentDiv = document.getElementById('page-content');
        if (contentDiv) {
            contentDiv.style.display = 'block';
        }
        this.hideAuthCheck();
    }

    // 验证token有效性
    async validateToken() {
        try {
            const response = await this.fetchWithAuth('/api/status');
            if (response && response.ok) {
                return true;
            }
            return false;
        } catch (error) {
            console.error('Token验证失败:', error);
            return false;
        }
    }

    // 初始化页面认证
    async initPageAuth() {
        this.showAuthCheck();
        
        if (!this.token) {
            this.showUnauthorized();
            setTimeout(() => this.redirectToLogin(), 2000);
            return false;
        }

        const isValid = await this.validateToken();
        if (isValid) {
            this.showContent();
            return true;
        } else {
            localStorage.removeItem('authToken');
            this.showUnauthorized();
            setTimeout(() => this.redirectToLogin(), 2000);
            return false;
        }
    }
}

// 全局认证管理器实例
window.authManager = new AuthManager();

// 页面加载完成后初始化认证
document.addEventListener('DOMContentLoaded', function() {
    if (window.authManager) {
        window.authManager.initPageAuth();
    }
});