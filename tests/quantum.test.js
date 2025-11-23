const { quantumControlCenter } = require('../owlban_revenue_repo/quantum/quantumControlCenter');
const { expect } = require('chai');

describe('Quantum Control Center', () => {
  it('should initialize quantum control center system', () => {
    const controlCenter = quantumControlCenter.initialize();
    expect(controlCenter).to.have.property('status');
    expect(controlCenter.status).to.equal('initialized');
  });

  it('should perform system health check', () => {
    const health = quantumControlCenter.healthCheck();
    expect(health).to.be.true;
  });
});
