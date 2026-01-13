// UBI Payment Service
import { info, error } from '../utils/loggerWrapper.js';
import UBIPayment from '../models/UBIPayment.js';
import Citizen from '../models/Citizen.js';

class UBIPaymentService {
  async calculateUBIAmount(citizenId) {
    const baseAmount = 2000; // Base UBI amount
    const citizen = await Citizen.findById(citizenId);
    if (!citizen) throw new Error('Citizen not found');
    
    // Calculate based on factors
    let amount = baseAmount;
    if (citizen.dependents) amount += citizen.dependents * 500;
    
    info(`UBI calculated for citizen ${citizenId}: $${amount}`);
    return amount;
  }

  async processPayment(citizenId) {
    try {
      const amount = await this.calculateUBIAmount(citizenId);
      const payment = new UBIPayment({
        citizenId,
        amount,
        status: 'processing'
      });
      
      await payment.save();
      info(`UBI payment initiated: ${payment._id}`);
      return payment;
    } catch (err) {
      error('UBI payment processing failed:', err);
      throw err;
    }
  }

  async getPaymentHistory(citizenId) {
    return await UBIPayment.find({ citizenId }).sort({ paymentDate: -1 });
  }
}

export default new UBIPaymentService();
