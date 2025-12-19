import { quantumAIWallet } from '../owlban_revenue_repo/quantum/quantumAIWallet.js';
import { expect } from 'chai';

describe('Quantum AI Wallet', () => {
  it('should generate a new wallet with valid keys', () => {
    const wallet = quantumAIWallet.createWallet();
    expect(wallet).to.have.property('publicKey');
    expect(wallet).to.have.property('privateKey');
  });

  it('should encrypt and decrypt messages correctly', () => {
    const wallet = quantumAIWallet.createWallet();
    const message = 'Hello Quantum';
    const encrypted = quantumAIWallet.encrypt(wallet.publicKey, message);
    expect(encrypted).to.not.equal(message);
    const decrypted = quantumAIWallet.decrypt(wallet.privateKey, encrypted);
    expect(decrypted).to.equal(message);
  });
});
