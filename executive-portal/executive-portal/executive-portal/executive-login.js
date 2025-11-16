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
        // Setup event listeners for login form
        const loginForm = document.getElementById('executive-login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', this.handleLogin.bind(this));
        }
    }

    setupFormValidation() {
        // Setup form validation
        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');

        if (emailInput) {
            emailInput.addEventListener('blur', this.validateEmail.bind(this));
        }
        if (passwordInput) {
            passwordInput.addEventListener('input', this.validatePassword.bind(this));
        }
    }

    setupPasswordStrength() {
        // Setup password strength indicator
        const passwordInput = document.getElementById('password');
        const strengthIndicator = document.getElementById('password-strength');

        if (passwordInput && strengthIndicator) {
            passwordInput.addEventListener('input', () => {
                const strength = this.calculatePasswordStrength(passwordInput.value);
                strengthIndicator.textContent = `Strength: ${strength}`;
            });
        }
    }

    setupTwoFactorAuth() {
        // Setup 2FA input handling
        const twoFactorInput = document.getElementById('two-factor-code');
        if (twoFactorInput) {
            twoFactorInput.addEventListener('input', this.validateTwoFactorCode.bind(this));
        }
    }

    handleLogin(event) {
        event.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const twoFactorCode = document.getElementById('two-factor-code').value;

        if (this.validateLogin(email, password, twoFactorCode)) {
            // Simulate login success
            alert('Login successful! Redirecting to executive dashboard...');
            // Redirect to dashboard
            globalThis.location.href = '/executive-dashboard';
        }
    }

    validateEmail() {
        const email = document.getElementById('email').value;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const isValid = emailRegex.test(email);
        this.showValidationMessage('email', isValid, 'Please enter a valid email address');
        return isValid;
    }

    validatePassword() {
        const password = document.getElementById('password').value;
        const isValid = password.length >= 8;
        this.showValidationMessage('password', isValid, 'Password must be at least 8 characters long');
        return isValid;
    }

    validateTwoFactorCode() {
        const code = document.getElementById('two-factor-code').value;
        const isValid = /^\d{6}$/.test(code);
        this.showValidationMessage('two-factor-code', isValid, 'Please enter a valid 6-digit code');
        return isValid;
    }

    validateLogin(_email, _password, _twoFactorCode) {
        return this.validateEmail() && this.validatePassword() && this.validateTwoFactorCode();
    }

    calculatePasswordStrength(password) {
        let strength = 0;
        if (password.length >= 8) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[a-z]/.test(password)) strength++;
        if (/\d/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;

        switch (strength) {
            case 0:
            case 1: return 'Very Weak';
            case 2: return 'Weak';
            case 3: return 'Medium';
            case 4: return 'Strong';
            case 5: return 'Very Strong';
            default: return 'Unknown';
        }
    }

    showValidationMessage(fieldId, isValid, message) {
        const field = document.getElementById(fieldId);
        const errorElement = document.getElementById(`${fieldId}-error`);

        if (errorElement) {
            if (isValid) {
                errorElement.style.display = 'none';
            } else {
                errorElement.textContent = message;
                errorElement.style.display = 'block';
            }
        }

        if (field) {
            if (isValid) {
                field.classList.remove('invalid');
            } else {
                field.classList.add('invalid');
            }
        }
    }
}

// Initialize the portal when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    globalThis.portal = new ExecutiveLoginPortal(); // Initialize the executive login portal
});
