const { QuantumControlCenter } = require('../quantum/quantumControlCenter');
const { expect } = require('chai');

describe('Quantum Control Center', () => {
  let controlCenter;

  beforeEach(() => {
    controlCenter = new QuantumControlCenter();
  });

  it('should initialize quantum control center system', async () => {
    // Wait for initialization to complete
    await new Promise((resolve) => setTimeout(resolve, 100));

    const status = controlCenter.getControlCenterStatus();
    expect(status).to.have.property('centerId');
    expect(status.centerId).to.match(/^QCC_/);
  });

  it('should perform system health check', () => {
    const status = controlCenter.getControlCenterStatus();
    expect(status).to.have.property('jpmorganConnection');
    expect(status).to.have.property('syncStatus');
  });
});
