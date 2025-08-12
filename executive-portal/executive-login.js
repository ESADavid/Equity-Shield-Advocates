// Executive Login Portal JavaScript - Oscar Broome
// Enhanced security and executive-level features

class ExecutiveLoginPortal {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupFormValidation();
        this.setupPasswordStrength();
        this.setupTwoFactorAuth();
    }

    setupEventListeners() {
        const form = document.getElementById('executiveLoginForm');
        const loginBtn = document.getElementById('loginBtn');
        const passwordInput = document.getElementById('executivePassword');
        const togglePassword = document.querySelector('.toggle-password');
        const resendCodeBtn = document.getElementById('resendCode');

        form.addEventListener('submit', (e) => this.handleLogin(e));
        passwordInput.addEventListener('input', (e) => this.updatePasswordStrength(e));
        togglePassword.addEventListener('click', () => this.togglePasswordVisibility());
        resendCodeBtn.addEventListener('click', () => this.resendTwoFactorCode());
    }

    setupFormValidation() {
        const inputs = document.querySelectorAll('.input-group input');
        inputs.forEach(input => {
            input.addEventListener('blur', () => this.validateField(input));
            input.addEventListener('focus', () => this.clearFieldError(input));
        });
    }

    setupPasswordStrength() {
        const passwordInput = document.getElementById('executivePassword');
        const strengthIndicator = document.getElementById('passwordStrength');
        
        passwordInput.addEventListener('input', (e) => {
            this.updatePasswordStrength(e);
        });
    }

    setupTwoFactorAuth() {
        // Simulate 2FA setup
        this.generateTwoFactorCode();
    }

    validateField(field) {
        const value = field.value.trim();
        const fieldName = field.name;
        
        let isValid = true;
        let errorMessage = '';

        switch (fieldName) {
            case 'email':
                if (!this.isValidEmail(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid executive email address';
                }
                break;
            case 'password':
                if (value.length < 8) {
                    isValid = false;
                    errorMessage = 'Password must be at least 8 characters';
                }
                break;
            case 'mfaCode':
                if (!/^\d{6}$/.test(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid 6-digit code';
                }
                break;
        }

        if (!isValid) {
            this.showFieldError(field, errorMessage);
        }

        return isValid;
    }

    validateField(field) {
        const value = field.value.trim();
        const fieldName = field.name;
        
        let isValid = true;
        let errorMessage = '';

        switch (fieldName) {
            case 'email':
                if (!this.isValidEmail(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid executive email address';
                }
                break;
            case 'password':
                if (value.length < 8) {
                    isValid = false;
                    errorMessage = 'Password must be at least 8 characters';
                }
                break;
            case 'mfaCode':
                if (!/^\d{6}$/.test(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid 6-digit code';
                }
                break;
        }

        if (!isValid) {
            this.showFieldError(field, errorMessage);
        }

        return isValid;
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    showFieldError(field, message) {
        const formGroup = field.closest('.form-group');
        const errorDiv = formGroup.querySelector('.error-message') || document.createElement('div');
        
        if (!formGroup.querySelector('.error-message')) {
            errorDiv.className = 'error-message';
            formGroup.appendChild(errorDiv);
        }
        
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    }

    clearFieldError(field) {
        const formGroup = field.closest('.form-group');
        const errorDiv = formGroup.querySelector('.error-message');
        if (errorDiv) {
            errorDiv.style.display = 'none';
        }
    }

    updatePasswordStrength(event) {
        const password = event.target.value;
        const strengthIndicator = document.getElementById('passwordStrength');
        
        if (!strengthIndicator) return;

        let strength = 0;
        
        if (password.length >= 8) strength += 1;
        if (/[a-z]/.test(password)) strength += 1;
        if (/[A-Z]/.test(password)) strength += 1;
        if (/[0-9]/.test(password)) strength += 1;
        if (/[^A-Za-z0-9]/.test(password)) strength += 1;

        let strengthClass = '';
        let strengthText = '';

        if (strength <= 2) {
            strengthClass = 'weak';
            strengthText = 'Weak';
        } else if (strength <= 4) {
            strengthClass = 'medium';
            strengthText = 'Medium';
        } else {
            strengthClass = 'strong';
            strengthText = 'Strong';
        }

        strengthIndicator.className = `password-strength ${strengthClass}`;
        strengthIndicator.textContent = strengthText;
    }

    togglePasswordVisibility() {
        const passwordInput = document.getElementById('executivePassword');
        const toggleIcon = document.querySelector('.toggle-password');
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleIcon.classList.remove('fa-eye');
            toggleIcon.classList.add('fa-eye-slash');
        } else {
            passwordInput.type = 'password';
            toggleIcon.classList.remove('fa-eye-slash');
            toggleIcon.classList.add('fa-eye');
        }
    }

    async handleLogin(event) {
        event.preventDefault();
        
        const form = event.target;
        const loginBtn = document.getElementById('loginBtn');
        const btnText = loginBtn.querySelector('.btn-text');
        const spinner = loginBtn.querySelector('.fa-spinner');
        
        // Disable button and show spinner
        loginBtn.disabled = true;
        btnText.style.display = 'none';
        spinner.style.display = 'inline-block';
        
        try {
            // Validate form
            const email = document.getElementById('executiveEmail').value.trim();
            const password = document.getElementById('executivePassword').value;
            const mfaCode = document.getElementById('mfaCode').value.trim();
            const rememberMe = document.getElementById('rememberMe').checked;
            
            if (!this.validateForm()) {
                throw new Error('Please correct the errors in the form');
            }
            
            // Simulate API call
            const response = await this.performLogin(email, password, mfaCode, rememberMe);
            
            if (response.success) {
                this.handleSuccessfulLogin(response, rememberMe);
            } else {
                this.handleLoginError(response.message);
            }
            
        } catch (error) {
            this.handleLoginError(error.message);
        } finally {
            // Re-enable button and hide spinner
            loginBtn.disabled = false;
            btnText.style.display = 'inline-block';
            spinner.style.display = 'none';
        }
    }

    validateForm() {
        const email = document.getElementById('executiveEmail').value.trim();
        const password = document.getElementById('executivePassword').value;
        const mfaCode = document.getElementById('mfaCode').value.trim();
        
        if (!this.isValidEmail(email)) {
            this.showFieldError(document.getElementById('executiveEmail'), 'Please enter a valid email');
            return false;
        }
        
        if (password.length < 8) {
            this.showFieldError(document.getElementById('executivePassword'), 'Password must be at least 8 characters');
            return false;
        }
        
        if (!/^\d{6}$/.test(mfaCode)) {
            this.showFieldError(document.getElementById('mfaCode'), 'Please enter a valid 6-digit code');
            return false;
        }
        
        return true;
    }

    async performLogin(email, password, mfaCode, rememberMe) {
        // Simulate API call
        return new Promise((resolve) => {
            setTimeout(() => {
                // Simulate successful login
                if (email.includes('executive') && password.length >= 8 && mfaCode === '123456') {
                    resolve({
                        success: true,
                        token: 'mock-jwt-token',
                        user: {
                            email: email,
                            role: 'executive',
                            name: 'Oscar Broome'
                        }
                    });
                } else {
                    resolve({
                        success: false,
                        message: 'Invalid credentials or 2FA code'
                    });
                }
            }, 2000);
        });
    }

    handleSuccessfulLogin(response, rememberMe) {
        // Store token and user info
        localStorage.setItem('executiveToken', response.token);
        localStorage.setItem('executiveUser', JSON.stringify(response.user));
        
        if (rememberMe) {
            localStorage.setItem('rememberMe', 'true');
        }
        
        // Redirect to dashboard
        window.location.href = '/executive-portal/dashboard.html';
    }

    handleLoginError(message) {
        this.showError(message);
    }

    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
        
        const form = document.getElementById('executiveLoginForm');
        form.appendChild(errorDiv);
        
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }

    async resendTwoFactorCode() {
        const resendBtn = document.getElementById('resendCode');
        resendBtn.disabled = true;
        resendBtn.textContent = 'Sending...';
        
        setTimeout(() => {
            resendBtn.disabled = false;
            resendBtn.textContent = 'Resend Code';
            this.showSuccess('2FA code resent to your registered device');
        }, 2000);
    }

    showSuccess(message) {
        const successDiv = document.createElement('div');
        successDiv.className = 'success-message';
        successDiv.textContent = message;
        successDiv.style.display = 'block';
        
        const form = document.getElementById('executiveLoginForm');
        form.appendChild(successDiv);
        
        setTimeout(() => {
            successDiv.remove();
        }, 3000);
    }

    generateTwoFactorCode() {
        // Simulate 2FA code generation
        console.log('2FA code generated: 123456');
    }
}

// Initialize the portal
document.addEventListener('DOMContentLoaded', () => {
    new ExecutiveLoginPortal();
});

// Additional utility functions
const Utils = {
    formatCurrency: (amount) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD'
        }).format(amount);
    },
    
    formatDate: (date) => {
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        }).format(new Date(date));
    },
    
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};

// Export for use in other modules
window.ExecutiveLoginPortal = ExecutiveLoginPortal;
window.Utils = Utils;
