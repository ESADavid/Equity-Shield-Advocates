describe('OWLban Earnings Dashboard', () => {
  it('loads the dashboard page and displays earnings data', () => {
    cy.visit('/', {
      auth: {
        username: 'admin',
        password: 'securepassword',
      },
    });
    cy.contains('OWLban Earnings Dashboard');
    cy.get('#earnings').should('not.be.empty');
    cy.get('#earnings').within(() => {
      cy.contains('Total Annual Revenue');
      cy.contains('Total Daily Revenue');
      cy.get('ul > li').should('have.length.greaterThan', 0);
    });
  });

  it('shows error message when API fails', () => {
    cy.intercept('/api/earnings', { statusCode: 500, body: {} });
    cy.visit('/', {
      auth: {
        username: 'admin',
        password: 'securepassword',
      },
    });
    cy.contains('Failed to load earnings data');
  });
});
