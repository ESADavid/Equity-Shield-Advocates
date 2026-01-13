// UBI Blockchain Ledger
import { info } from '../utils/loggerWrapper.js';
import blockchainService from './blockchainService.js';

class UBILedger {
  async recordPayment(payment) {
    const record = {
      type: 'UBI_PAYMENT',
      citizenId: payment.citizenId,
      amount: payment.amount,
      timestamp: new Date(),
      paymentId: payment._id
    };
    
    const hash = await blockchainService.addBlock(record);
    info(`UBI payment recorded on blockchain: ${hash}`);
    return hash;
  }

  async verifyPayment(paymentId) {
    return await blockchainService.verifyBlock(paymentId);
  }
}

export default new UBILedger();
