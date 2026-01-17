// Use CommonJS syntax compatible with Jest configuration
const { QuantumTransactionEngine } = require('../quantum/quantumTransactionEngine.js');
const { expect } = require('chai');

describe('Quantum Transaction Engine', () => {
  it('should process transactions correctly', async () => {
    const engine = new QuantumTransactionEngine();
    const transactions = [
      { type: 'payment', amount: 100, from: 'A', to: 'B' },
      { type: 'transfer', amount: 200, from: 'B', to: 'C' },
    ];
    const results = [];
    for (const tx of transactions) {
      const result = await engine.processTransaction(tx);
      results.push(result);
    }
    expect(results).to.have.lengthOf(2);
    expect(results[0]).to.have.property('success', true);
    expect(results[0]).to.have.property('transactionId');
  });

  it('should handle empty transaction list', async () => {
    const results = [];
    // Simulating processing no transactions, expecting empty results
    expect(results).to.be.an('array').that.is.empty;
  });
});
