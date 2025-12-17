/* eslint-env cypress */

// End-to-End Tests for Oscar Broome Executive Portal
// Comprehensive E2E testing covering login, 2FA, dashboard, and all critical flows

describe('Oscar Broome Executive Portal E2E Tests', () => {
  const baseUrl = 'http://localhost:4000';
  const executivePortalUrl = `${baseUrl}/executive-portal/login.html`;
  const dashboardUrl = `${baseUrl}/executive-portal/dashboard.html`;

  beforeEach(() => {
    // Clear local storage before each test
    cy.clearLocalStorage();
  });

  describe('Executive Login Portal', () => {
    it('should load the executive login page', () => {
      cy.visit(executivePortalUrl);
      cy.contains('Oscar Broome');
      cy.contains('Executive Revenue Portal');
      cy.get('#executiveLoginForm').should('be.visible');
    });

    it('should validate email format', () => {
      cy.visit(executivePortalUrl);
      cy.get('#executiveEmail').type('invalid-email');
      cy.get('#executivePassword').type('password123');
      cy.get('#mfaCode').type('123456');
      cy.get('#executiveLoginForm').submit();
      cy.contains('Please enter a valid email').should('be.visible');
    });

    it('should validate password length', () => {
      cy.visit(executivePortalUrl);
      cy.get('#executiveEmail').type('executive@oscarbroome.com');
      cy.get('#executivePassword').type('short');
      cy.get('#mfaCode').type('123456');
      cy.get('#executiveLoginForm').submit();
      cy.contains('Password must be at least 8 characters').should('be.visible');
    });

    it('should validate 2FA code format', () => {
      cy.visit(executivePortalUrl);
      cy.get('#executiveEmail').type('executive@oscarbroome.com');
      cy.get('#executivePassword').type('securepassword123');
      cy.get('#mfaCode').type('123');
      cy.get('#executiveLoginForm').submit();
      cy.contains('Please enter a valid 6-digit code').should('be.visible');
    });

    it('should successfully login with valid credentials', () => {
      cy.visit(executivePortalUrl);
      cy.get('#executiveEmail').type('executive@oscarbroome.com');
      cy.get('#executivePassword').type('securepassword123');
      cy.get('#mfaCode').type('123456');
      cy.get('#loginBtn').click();
      
      // Mock successful login
      cy.window().then((win) => {
        win.localStorage.setItem('executiveToken', 'mock-jwt-token');
        win.localStorage.setItem('executiveUser', JSON.stringify({
          email: 'executive@oscarbroome.com',
          name: 'Oscar Broome'
        }));
      });
      
      cy.url().should('include', 'dashboard.html');
    });

    it('should handle login failure gracefully', () => {
      cy.visit(executivePortalUrl);
      cy.get('#executiveEmail').type('wrong@email.com');
      cy.get('#executivePassword').type('wrongpassword');
      cy.get('#mfaCode').type('000000');
      cy.get('#loginBtn').click();
      
      // Mock failed login
      cy.contains('Invalid credentials').should('be.visible');
    });
  });

  describe('Executive Dashboard', () => {
    beforeEach(() => {
      // Set up authentication for dashboard tests
      cy.window().then((win) => {
        win.localStorage.setItem('executiveToken', 'mock-jwt-token');
        win.localStorage.setItem('executiveUser', JSON.stringify({
          email: 'executive@oscarbroome.com',
          name: 'Oscar Broome'
        }));
      });
    });

    it('should load the executive dashboard', () => {
      cy.visit(dashboardUrl);
      cy.contains('Executive Overview');
      cy.get('.metrics-grid').should('be.visible');
      cy.get('#revenueChart').should('be.visible');
      cy.get('#fleetChart').should('be.visible');
    });

    it('should display correct executive metrics', () => {
      cy.intercept('/api/earnings', {
        totalAnnualRevenue: 5000000,
        totalDailyRevenue: 13698.63,
        purchases: {
          autoFleetDetails: [
            { model: 'Tesla Model S', vin: '12345', cost: 79999, deliveryStatus: 'delivered' },
            { model: 'BMW X5', vin: '67890', cost: 60999, deliveryStatus: 'pending' }
          ],
          corporateHomes: 2500000
        }
      }).as('getEarnings');

      cy.visit(dashboardUrl);
      cy.wait('@getEarnings');
      
      cy.get('#totalRevenue').should('contain', '$5,000,000');
      cy.get('#dailyRevenue').should('contain', '$13,698.63');
      cy.get('#fleetCount').should('contain', '2');
      cy.get('#corporateHomes').should('contain', '$2,500,000');
    });

    it('should navigate between dashboard sections', () => {
      cy.visit(dashboardUrl);
      
      // Test navigation to Revenue section
      cy.get('[data-section="revenue"]').click();
      cy.get('#revenue-section').should('have.class', 'active');
      
      // Test navigation to Fleet section
      cy.get('[data-section="fleet"]').click();
      cy.get('#fleet-section').should('have.class', 'active');
      
      // Test navigation to Analytics section
      cy.get('[data-section="analytics"]').click();
      cy.get('#analytics-section').should('have.class', 'active');
    });

    it('should handle API errors gracefully', () => {
      cy.intercept('/api/earnings', { statusCode: 500, body: {} });
      cy.visit(dashboardUrl);
      
      cy.contains('Failed to load executive data').should('be.visible');
    });

    it('should logout and redirect to login', () => {
      cy.visit(dashboardUrl);
      cy.get('.logout-btn').click();

      cy.window().then((win) => {
        cy.wrap(win.localStorage.getItem('executiveToken')).should('be.null');
        cy.wrap(win.localStorage.getItem('executiveUser')).should('be.null');
      });

      cy.url().should('include', 'login.html');
    });
  });

  describe('Fleet Management', () => {
    beforeEach(() => {
      cy.window().then((win) => {
        win.localStorage.setItem('executiveToken', 'mock-jwt-token');
      });
    });

    it('should display fleet vehicles correctly', () => {
      cy.intercept('/api/earnings', {
        purchases: {
          autoFleetDetails: [
            { model: 'Tesla Model S', vin: '12345', cost: 79999, deliveryStatus: 'delivered' },
            { model: 'BMW X5', vin: '67890', cost: 60999, deliveryStatus: 'pending' }
          ]
        }
      });

      cy.visit(dashboardUrl);
      cy.get('[data-section="fleet"]').click();
      
      cy.contains('Tesla Model S').should('be.visible');
      cy.contains('BMW X5').should('be.visible');
      cy.contains('delivered').should('be.visible');
      cy.contains('pending').should('be.visible');
    });

    it('should allow marking vehicles as delivered', () => {
      cy.intercept('/api/delivery/mark-delivered', { message: 'Car marked as delivered' });
      
      cy.visit(dashboardUrl);
      cy.get('[data-section="fleet"]').click();
      
      cy.get('.btn-small').first().click();
      cy.contains('Vehicle 12345 marked as delivered').should('be.visible');
    });
  });

  describe('Revenue Management', () => {
    beforeEach(() => {
      cy.window().then((win) => {
        win.localStorage.setItem('executiveToken', 'mock-jwt-token');
      });
    });

    it('should sync revenue data', () => {
      cy.intercept('/api/sync/all', { message: 'Data synchronization completed successfully' });
      
      cy.visit(dashboardUrl);
      cy.get('[data-section="revenue"]').click();
      
      cy.contains('Sync Data').click();
      cy.contains('Revenue data synchronized successfully').should('be.visible');
    });

    it('should download revenue report', () => {
      cy.intercept('/api/earnings/download', {
        fixture: 'earnings_report.json'
      });
      
      cy.visit(dashboardUrl);
      cy.get('[data-section="revenue"]').click();
      
      cy.window().then((win) => {
        cy.stub(win, 'open').as('windowOpen');
      });
      
      cy.contains('Download Report').click();
      cy.get('@windowOpen').should('have.been.calledWith', '/api/earnings/download');
    });
  });

  describe('Responsive Design', () => {
    it('should be responsive on mobile devices', () => {
      cy.viewport(375, 667);
      cy.visit(executivePortalUrl);
      
      cy.get('.login-container').should('be.visible');
      cy.get('.login-form').should('be.visible');
    });

    it('should be responsive on tablet devices', () => {
      cy.viewport(768, 1024);
      cy.visit(executivePortalUrl);
      
      cy.get('.login-container').should('be.visible');
      cy.get('.login-form').should('be.visible');
    });
  });

  describe('Security Tests', () => {
    it('should redirect to login if not authenticated', () => {
      cy.clearLocalStorage();
      cy.visit(dashboardUrl);
      cy.url().should('include', 'login.html');
    });

    it('should handle expired tokens', () => {
      cy.window().then((win) => {
        win.localStorage.setItem('executiveToken', 'expired-token');
      });
      
      cy.intercept('/api/earnings', { statusCode: 401 });
      cy.visit(dashboardUrl);
      
      cy.url().should('include', 'login.html');
    });
  });
});
