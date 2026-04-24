import { info, error, warn, debug } from 'utils/loggerWrapper.js';

/**
 * Oscar Broome Login Override Dashboard JavaScript
 * Frontend interface for emergency access and administrative overrides
 */

class OverrideDashboard {
  constructor() {
    this.currentSection = 'emergency';
    this.apiBaseUrl = '/api/override';
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.loadStats();
    this.checkAuthentication();
  }

  setupEventListeners() {
    // Tab switching
    const tabs = document.querySelectorAll('.override-tab');
    tabs.forEach((tab) => {
      tab.addEventListener('click', (e) => {
        const section = e.target.dataset.section;
        this.switchSection(section);
      });
    });

    // Form submissions
    const emergencyForm = document.getElementById('emergencyForm');
    const adminForm = document.getElementById('adminForm');
    const technicalForm = document.getElementById('technicalForm');

    emergencyForm.addEventListener('submit', (e) =>
      this.handleEmergencyOverride(e)
    );
    adminForm.addEventListener('submit', (e) => this.handleAdminOverride(e));
    technicalForm.addEventListener('submit', (e) =>
      this.handleTechnicalOverride(e)
    );

    // Input validation
    this.setupFormValidation();
  }

  switchSection(section) {
    // Update active tab
    document.querySelectorAll('.override-tab').forEach((tab) => {
      tab.classList.remove('active');
    });
    document
      .querySelector(`[data-section="${section}"]`)
      .classList.add('active');

    // Update active section
    document.querySelectorAll('.override-section').forEach((sec) => {
      sec.classList.remove('active');
    });
    document.getElementById(`${section}-section`).classList.add('active');

    this.currentSection = section;

    // Load section-specific data
    if (section === 'management') {
      this.loadStats();
    }
  }

  setupFormValidation() {
    // Real-time validation for ticket number
    const ticketInput = document.getElementById('ticketNumber');
    ticketInput.addEventListener('input', (e) => {
      const value = e.target.value;
      const pattern = /^[A-Z]{2,4}-\d{4,6}$/;
      const isValid = pattern.test(value);

      e.target.style.borderColor = isValid ? '#28a745' : '#dc3545';
    });

    // Emergency code masking
    const emergencyCodeInput = document.getElementById('emergencyCode');
    emergencyCodeInput.addEventListener('input', (e) => {
      // Mask the input for security
      const value = e.target.value;
      if (value.length > 0) {
        e.target.type = 'password';
      }
    });
  }

  async handleEmergencyOverride(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const data = {
      userId: formData.get('userId'),
      reason: formData.get('reason'),
      emergencyCode: formData.get('emergencyCode'),
      additionalAuth: formData.get('additionalAuth'),
    };

    this.setLoading('emergencyBtn', true);

    try {
      const response = await this.makeApiCall('/emergency', 'POST', data);

      if (response.success) {
        this.showSuccess(
          `Emergency override activated successfully! Override ID: ${response.data.overrideId}`
        );
        this.clearForm('emergencyForm');
        this.loadStats(); // Refresh stats
      } else {
        this.showError(response.error || 'Emergency override failed');
      }
    } catch (error) {
      this.showError('Network error occurred. Please try again.');
      logger.error('Emergency override error:', error);
    } finally {
      this.setLoading('emergencyBtn', false);
    }
  }

  async handleAdminOverride(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const data = {
      adminUserId: formData.get('adminUserId'),
      targetUserId: formData.get('targetUserId'),
      reason: formData.get('reason'),
      justification: formData.get('justification'),
    };

    this.setLoading('adminBtn', true);

    try {
      const response = await this.makeApiCall('/admin', 'POST', data);

      if (response.success) {
        this.showSuccess(
          `Admin override activated successfully! Override ID: ${response.data.overrideId}`
        );
        this.clearForm('adminForm');
        this.loadStats(); // Refresh stats
      } else {
        this.showError(response.error || 'Admin override failed');
      }
    } catch (error) {
      this.showError('Network error occurred. Please try again.');
      logger.error('Admin override error:', error);
    } finally {
      this.setLoading('adminBtn', false);
    }
  }

  async handleTechnicalOverride(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const data = {
      supportUserId: formData.get('supportUserId'),
      targetUserId: formData.get('targetUserId'),
      reason: formData.get('reason'),
      ticketNumber: formData.get('ticketNumber'),
    };

    this.setLoading('technicalBtn', true);

    try {
      const response = await this.makeApiCall('/technical', 'POST', data);

      if (response.success) {
        this.showSuccess(
          `Technical override activated successfully! Override ID: ${response.data.overrideId}`
        );
        this.clearForm('technicalForm');
        this.loadStats(); // Refresh stats
      } else {
        this.showError(response.error || 'Technical override failed');
      }
    } catch (error) {
      this.showError('Network error occurred. Please try again.');
      logger.error('Technical override error:', error);
    } finally {
      this.setLoading('technicalBtn', false);
    }
  }

  async makeApiCall(endpoint, method, data) {
    const url = `${this.apiBaseUrl}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${localStorage.getItem('adminToken') || localStorage.getItem('executiveToken')}`,
    };

    const response = await fetch(url, {
      method: method,
      headers: headers,
      body: method !== 'GET' ? JSON.stringify(data) : undefined,
    });

    if (!response.ok) {
      const errorData = await response
        .json()
        .catch(() => ({ error: 'Network error' }));
      throw new Error(errorData.error || `HTTP ${response.status}`);
    }

    return await response.json();
  }

  async loadStats() {
    try {
      const response = await this.makeApiCall('/stats', 'GET');

      if (response.success) {
        this.updateStatsDisplay(response.data);
      }
    } catch (error) {
      logger.error('Failed to load stats:', error);
      this.showError('Failed to load override statistics');
    }
  }

  updateStatsDisplay(stats) {
    document.getElementById('activeOverridesCount').textContent =
      stats.totalActive || 0;
    document.getElementById('emergencyOverridesCount').textContent =
      stats.byType?.emergency || 0;
    document.getElementById('adminOverridesCount').textContent =
      stats.byType?.admin || 0;
    document.getElementById('technicalOverridesCount').textContent =
      stats.byType?.technical || 0;

    this.updateActiveOverridesList(stats.recentActivity || []);
  }

  updateActiveOverridesList(overrides) {
    const container = document.getElementById('activeOverridesList');

    if (overrides.length === 0) {
      container.innerHTML = '<p>No active override sessions</p>';
      return;
    }

    const overridesHtml = overrides
      .map(
        (override) => `
            <div class="override-item ${override.type}">
                <div class="override-info">
                    <div class="override-details">
                        <strong>${override.type.toUpperCase()} OVERRIDE</strong><br>
                        ID: ${override.id}<br>
                        Reason: ${override.reason}<br>
                        Created: ${new Date(override.timestamp).toLocaleString()}
                    </div>
                    <div class="override-actions">
                        <button class="btn-small btn-danger" onclick="revokeOverride('${override.id}')">
                            Revoke
                        </button>
                    </div>
                </div>
            </div>
        `
      )
      .join('');

    container.innerHTML = overridesHtml;
  }

  async revokeOverride(overrideId) {
    if (!confirm('Are you sure you want to revoke this override session?')) {
      return;
    }

    const reason = prompt(
      'Please provide a reason for revoking this override:'
    );
    if (!reason) {
      return;
    }

    try {
      const response = await this.makeApiCall(`/revoke/${overrideId}`, 'POST', {
        revokedBy: 'admin@oscarsystem.com', // In real implementation, get from current user
        reason: reason,
      });

      if (response.success) {
        this.showSuccess('Override session revoked successfully');
        this.loadStats(); // Refresh the list
      } else {
        this.showError(response.error || 'Failed to revoke override');
      }
    } catch (error) {
      this.showError('Failed to revoke override session');
      logger.error('Revoke error:', error);
    }
  }

  checkAuthentication() {
    const token =
      localStorage.getItem('adminToken') ||
      localStorage.getItem('executiveToken');

    if (!token) {
      this.showWarning('Authentication required. Please log in first.');
      setTimeout(() => {
        window.location.href = '/executive-portal/login.html';
      }, 3000);
    }
  }

  setLoading(buttonId, loading) {
    const button = document.getElementById(buttonId);
    const btnText = button.querySelector('.btn-text');
    const loadingSpinner = button.querySelector('.loading');

    button.disabled = loading;
    btnText.style.display = loading ? 'none' : 'inline-block';
    loadingSpinner.classList.toggle('hidden', !loading);
  }

  clearForm(formId) {
    const form = document.getElementById(formId);
    form.reset();

    // Clear any validation styling
    const inputs = form.querySelectorAll('input, select, textarea');
    inputs.forEach((input) => {
      input.style.borderColor = '';
    });
  }

  showSuccess(message) {
    const alert = document.getElementById('successAlert');
    const messageSpan = document.getElementById('successMessage');

    messageSpan.textContent = message;
    alert.style.display = 'block';

    // Hide after 5 seconds
    setTimeout(() => {
      alert.style.display = 'none';
    }, 5000);

    // Hide other alerts
    this.hideAlerts(['errorAlert', 'warningAlert']);
  }

  showError(message) {
    const alert = document.getElementById('errorAlert');
    const messageSpan = document.getElementById('errorMessage');

    messageSpan.textContent = message;
    alert.style.display = 'block';

    // Hide after 5 seconds
    setTimeout(() => {
      alert.style.display = 'none';
    }, 5000);

    // Hide other alerts
    this.hideAlerts(['successAlert', 'warningAlert']);
  }

  showWarning(message) {
    const alert = document.getElementById('warningAlert');
    const messageSpan = document.getElementById('warningMessage');

    messageSpan.textContent = message;
    alert.style.display = 'block';

    // Hide after 5 seconds
    setTimeout(() => {
      alert.style.display = 'none';
    }, 5000);

    // Hide other alerts
    this.hideAlerts(['successAlert', 'errorAlert']);
  }

  hideAlerts(alertIds) {
    alertIds.forEach((id) => {
      document.getElementById(id).style.display = 'none';
    });
  }

  // Utility function to format dates
  formatDate(dateString) {
    return new Date(dateString).toLocaleString();
  }

  // Utility function to format time remaining
  formatTimeRemaining(expiresAt) {
    const now = new Date();
    const expires = new Date(expiresAt);
    const diff = expires - now;

    if (diff <= 0) {
      return 'Expired';
    }

    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;

    if (hours > 0) {
      return `${hours}h ${remainingMinutes}m`;
    } else {
      return `${remainingMinutes}m`;
    }
  }
}

// Global functions for HTML onclick handlers
function revokeOverride(overrideId) {
  if (window.overrideDashboard) {
    window.overrideDashboard.revokeOverride(overrideId);
  }
}

function refreshStats() {
  if (window.overrideDashboard) {
    window.overrideDashboard.loadStats();
  }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.overrideDashboard = new OverrideDashboard();
});

// Auto-refresh stats every 30 seconds
setInterval(() => {
  if (window.overrideDashboard) {
    window.overrideDashboard.loadStats();
  }
}, 30000);
