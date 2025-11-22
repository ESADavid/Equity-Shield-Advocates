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
            emailInput.addEventListener('blur', this.validateEmailExecutive.bind(this));
        }
        if (passwordInput) {
            passwordInput.addEventListener('input', this.validatePasswordExecutive.bind(this));
        }
    }

    setupPasswordStrength() {
        // Setup password strength indicator
        const passwordInput = document.getElementById('password');
        const strengthIndicator = document.getElementById('password-strength');

        if (passwordInput && strengthIndicator) {
            passwordInput.addEventListener('input', () => {
                const strength = this.calculatePasswordStrengthExecutive(passwordInput.value);
                strengthIndicator.textContent = `Strength: ${strength}`;
                this.updateStrengthColorExecutive(strengthIndicator, strength);
            });
        }
    }

    setupTwoFactorAuth() {
        // Setup 2FA input handling
        const twoFactorInput = document.getElementById('two-factor-code');
        if (twoFactorInput) {
            twoFactorInput.addEventListener('input', this.validateTwoFactorCodeExecutive.bind(this));
        }
    }

    handleLogin(event) {
        event.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const twoFactorCode = document.getElementById('two-factor-code').value;

        if (this.validateLoginExecutive(email, password, twoFactorCode)) {
            // Simulate login success
            alert('Login successful! Redirecting to executive dashboard...');
            // Redirect to dashboard
            window.location.href = '/executive-dashboard';
        }
    }

    validateEmailExecutive() {
        const email = document.getElementById('email').value;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const isValid = emailRegex.test(email);
        this.showValidationMessageExecutive('email', isValid, 'Please enter a valid email address');
        return isValid;
    }

    validatePasswordExecutive() {
        const password = document.getElementById('password').value;
        const isValid = password.length >= 8;
        this.showValidationMessageExecutive('password', isValid, 'Password must be at least 8 characters long');
        return isValid;
    }

    validateTwoFactorCodeExecutive() {
        const code = document.getElementById('two-factor-code').value;
        const isValid = /^\d{6}$/.test(code);
        this.showValidationMessageExecutive('two-factor-code', isValid, 'Please enter a valid 6-digit code');
        return isValid;
    }

    validateLoginExecutive(email, password, twoFactorCode) {
        return this.validateEmailExecutive() && this.validatePasswordExecutive() && this.validateTwoFactorCodeExecutive();
    }

    calculatePasswordStrengthExecutive(password) {
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

    updateStrengthColorExecutive(element, strength) {
        // Remove existing strength classes
        element.classList.remove('very-weak', 'weak', 'medium', 'strong', 'very-strong');

        // Add appropriate class
        switch (strength) {
            case 'Very Weak':
                element.classList.add('very-weak');
                break;
            case 'Weak':
                element.classList.add('weak');
                break;
            case 'Medium':
                element.classList.add('medium');
                break;
            case 'Strong':
                element.classList.add('strong');
                break;
            case 'Very Strong':
                element.classList.add('very-strong');
                break;
        }
    }

    showValidationMessageExecutive(fieldId, isValid, message) {
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
            field.classList.toggle('invalid', isValid === false);
        }
    }
}

// Initialize the portal when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    globalThis.portal = new ExecutiveLoginPortal(); // Initialize the executive login portal
});
