// UBI Payment Service - Integrated with Payroll & JPMorgan
import { info, error, warn } from '../utils/loggerWrapper.js';
import UBIPayment from '../models/UBIPayment.js';
import Citizen from '../models/Citizen.js';
import axios from 'axios';
import crypto from 'crypto';

class UBIPaymentService {
  constructor() {
    // JPMorgan configuration
    this.jpmorganConfig = {
      clientId: process.env.JPMORGAN_CLIENT_ID,
      clientSecret: process.env.JPMORGAN_CLIENT_SECRET,
      baseUrl:
        process.env.JPMORGAN_BASE_URL ||
        'https://api-mock.payments.jpmorgan.com',
      organizationId: process.env.JPMORGAN_ORGANIZATION_ID,
      projectId: process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V',
      merchantId: process.env.JPMORGAN_MERCHANT_ID,
      terminalId: process.env.JPMORGAN_TERMINAL_ID,
    };
  }

  // Generate JPMorgan authentication headers
  generateJPMorganHeaders() {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('hex');
    const message = `${this.jpmorganConfig.clientId}${timestamp}${nonce}`;
    const signature = crypto
      .createHmac('sha256', this.jpmorganConfig.clientSecret)
      .update(message)
      .digest('base64');

    return {
      'Content-Type': 'application/json',
      'Client-Id': this.jpmorganConfig.clientId,
      Timestamp: timestamp.toString(),
      Nonce: nonce,
      Signature: signature,
      'Merchant-Id': this.jpmorganConfig.merchantId,
      'Terminal-Id': this.jpmorganConfig.terminalId,
    };
  }

  async calculateUBIAmount(citizenId) {
    const baseAmount = 2000; // Base UBI amount per month
    const citizen = await Citizen.findById(citizenId);
    if (!citizen) throw new Error('Citizen not found');

    // Calculate based on citizen data
    let amount = baseAmount;

    // Add dependents bonus
    if (citizen.dependents && citizen.dependents > 0) {
      amount += citizen.dependents * 500;
    }

    // Add housing assistance if applicable
    if (
      citizen.housingStatus === 'rented' ||
      citizen.housingStatus === 'homeless'
    ) {
      amount += 300;
    }

    // Add education bonus for students
    if (citizen.educationLevel === 'student') {
      amount += 200;
    }

    // Add disability support
    if (citizen.disabilityStatus) {
      amount += 400;
    }

    info(`UBI calculated for citizen ${citizenId}: $${amount.toFixed(2)}`);
    return amount;
  }

  async processPaymentViaJPMorgan(citizenId, amount, citizenData) {
    try {
      const headers = this.generateJPMorganHeaders();

      const orderId = `UBI-${citizenId}-${Date.now()}`;

      const paymentData = {
        amount: {
          value: amount,
          currency: 'USD',
        },
        order: {
          id: orderId,
          description: `Universal Basic Income Payment for Citizen ${citizenId}`,
        },
        customer: {
          id: citizenId,
          name: citizenData.name || 'Citizen',
          email: citizenData.email,
        },
        merchant: {
          id: this.jpmorganConfig.merchantId,
          terminalId: this.jpmorganConfig.terminalId,
        },
        paymentMethod: {
          type: 'BANK_TRANSFER', // Direct deposit for UBI
        },
      };

      const response = await axios.post(
        `${this.jpmorganConfig.baseUrl}/organizations/${this.jpmorganConfig.organizationId}/projects/${this.jpmorganConfig.projectId}/v1/payments`,
        paymentData,
        { headers, timeout: 30000 }
      );

      info(
        `JPMorgan payment created for citizen ${citizenId}: ${response.data.id}`
      );
      return {
        paymentId: response.data.id,
        status: response.data.status,
        authorizationCode: response.data.authorizationCode,
        orderId,
      };
    } catch (err) {
      error(
        'JPMorgan payment processing failed:',
        err.response?.data || err.message
      );
      throw new Error(
        `JPMorgan payment failed: ${err.response?.data?.message || err.message}`
      );
    }
  }

  async recordInPayrollSystem(citizenId, amount, paymentId) {
    try {
      // This would integrate with the payroll system to record UBI as a special payroll entry
      // For now, we'll log the intent - full integration would require payroll system API
      info(
        `Recording UBI payment in payroll system: Citizen ${citizenId}, Amount $${amount}, Payment ID ${paymentId}`
      );

      // Placeholder for payroll system integration
      // const payrollRecord = {
      //   employeeId: citizenId,
      //   payPeriod: new Date().toISOString().split('T')[0],
      //   earnings: { ubi: amount },
      //   paymentId,
      //   type: 'UBI'
      // };

      return true;
    } catch (err) {
      warn(
        'Failed to record in payroll system, continuing with payment:',
        err.message
      );
      return false;
    }
  }

  async processPayment(citizenId) {
    try {
      info(`Starting UBI payment process for citizen: ${citizenId}`);

      // Convert string citizenId to ObjectId if needed
      const citizenObjectId =
        typeof citizenId === 'string' ? citizenId : citizenId.toString();

      // Get citizen data
      const citizen = await Citizen.findById(citizenObjectId);
      if (!citizen) {
        throw new Error('Citizen not found');
      }

      // Check if citizen is eligible for UBI
      if (!citizen.isActive || citizen.ubiStatus === 'suspended') {
        throw new Error('Citizen not eligible for UBI payments');
      }

      // Check for recent payments (prevent duplicate monthly payments)
      const recentPayment = await UBIPayment.findOne({
        citizenId: citizenObjectId,
        paymentDate: {
          $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
        },
        status: { $in: ['completed', 'processing'] },
      });

      if (recentPayment) {
        throw new Error('UBI payment already processed for this month');
      }

      // Calculate UBI amount
      const amount = await this.calculateUBIAmount(citizenObjectId);

      // Create UBI payment record
      const payment = new UBIPayment({
        citizenId: citizenObjectId,
        amount,
        status: 'processing',
        paymentMethod: 'jpmorgan',
        metadata: {
          citizenName: citizen.name,
          citizenEmail: citizen.email,
          calculatedAt: new Date(),
        },
      });

      await payment.save();
      info(`UBI payment record created: ${payment._id}`);

      // Process payment via JPMorgan
      const jpmorganResult = await this.processPaymentViaJPMorgan(
        citizenId,
        amount,
        citizen
      );

      // Update payment record with JPMorgan details
      payment.transactionId = jpmorganResult.paymentId;
      payment.status =
        jpmorganResult.status === 'AUTHORIZED' ? 'completed' : 'processing';
      payment.metadata.jpmorganOrderId = jpmorganResult.orderId;
      payment.metadata.authorizationCode = jpmorganResult.authorizationCode;

      await payment.save();

      // Record in payroll system (async - don't block on failure)
      this.recordInPayrollSystem(
        citizenId,
        amount,
        jpmorganResult.paymentId
      ).catch((err) => {
        warn('Payroll system recording failed:', err.message);
      });

      info(`UBI payment completed successfully: ${payment._id}`);
      return payment;
    } catch (err) {
      error('UBI payment processing failed:', err);

      // Create failed payment record if we got far enough
      try {
        await UBIPayment.create({
          citizenId,
          amount: 0,
          status: 'failed',
          metadata: {
            error: err.message,
            failedAt: new Date(),
          },
        });
      } catch (recordErr) {
        error('Failed to record payment failure:', recordErr);
      }

      throw err;
    }
  }

  async getPaymentHistory(citizenId, limit = 50) {
    try {
      const payments = await UBIPayment.find({ citizenId })
        .sort({ paymentDate: -1 })
        .limit(limit)
        .populate('citizenId', 'name email');

      return payments;
    } catch (err) {
      error('Failed to get payment history:', err);
      throw err;
    }
  }

  async getPaymentStatus(paymentId) {
    try {
      const payment = await UBIPayment.findById(paymentId);
      if (!payment) {
        throw new Error('Payment not found');
      }

      // If payment is still processing, check JPMorgan status
      if (payment.status === 'processing' && payment.transactionId) {
        try {
          const headers = this.generateJPMorganHeaders();
          const response = await axios.get(
            `${this.jpmorganConfig.baseUrl}/organizations/${this.jpmorganConfig.organizationId}/projects/${this.jpmorganConfig.projectId}/v1/payments/${payment.transactionId}`,
            { headers }
          );

          // Update local status based on JPMorgan status
          const jpmorganStatus = response.data.status;
          if (jpmorganStatus === 'CAPTURED' || jpmorganStatus === 'SETTLED') {
            payment.status = 'completed';
          } else if (
            jpmorganStatus === 'FAILED' ||
            jpmorganStatus === 'VOIDED'
          ) {
            payment.status = 'failed';
          }

          payment.metadata.lastStatusCheck = new Date();
          await payment.save();
        } catch (statusErr) {
          warn('Failed to check JPMorgan payment status:', statusErr.message);
        }
      }

      return payment;
    } catch (err) {
      error('Failed to get payment status:', err);
      throw err;
    }
  }

  async processBulkPayments(citizenIds) {
    const results = {
      successful: [],
      failed: [],
      total: citizenIds.length,
    };

    info(
      `Starting bulk UBI payment processing for ${citizenIds.length} citizens`
    );

    for (const citizenId of citizenIds) {
      try {
        const payment = await this.processPayment(citizenId);
        results.successful.push({
          citizenId,
          paymentId: payment._id,
          amount: payment.amount,
        });
      } catch (err) {
        results.failed.push({
          citizenId,
          error: err.message,
        });
        error(`Bulk payment failed for citizen ${citizenId}:`, err.message);
      }
    }

    info(
      `Bulk UBI payment processing completed: ${results.successful.length} successful, ${results.failed.length} failed`
    );
    return results;
  }
}

export default new UBIPaymentService();
