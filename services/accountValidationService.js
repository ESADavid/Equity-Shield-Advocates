/**
 * ACCOUNT VALIDATION SERVICE
 * Validates banking accounts, routing numbers, and account balances
 * Provides comprehensive account verification and status checking
 */

import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'url';
import path from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class AccountValidationService {
  constructor() {
    this.validatedAccounts = new Map();
    this.validationHistory = [];
    this.accountCache = new Map();
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Validate account number using ABA routing number checksum
   * @param {string} accountNumber - Account number to validate
   * @param {string} routingNumber - ABA routing number
   * @returns {Object} Validation result
   */
  validateAccountNumber(accountNumber, routingNumber) {
    try {
      // Basic account number validation
      if (!accountNumber || typeof accountNumber !== 'string') {
        return {
          valid: false,
          error: 'Account number is required and must be a string',
          accountNumber: null
        };
      }

      // Remove spaces and dashes
      const cleanAccountNumber = accountNumber.replace(/[\s-]/g, '');

      // Check length (typically 8-17 digits)
      if (cleanAccountNumber.length < 8 || cleanAccountNumber.length > 17) {
        return {
          valid: false,
          error: 'Account number must be 8-17 digits long',
          accountNumber: cleanAccountNumber
        };
      }

      // Check if all characters are digits
      if (!/^\d+$/.test(cleanAccountNumber)) {
        return {
          valid: false,
          error: 'Account number must contain only digits',
          accountNumber: cleanAccountNumber
        };
      }

      // Validate routing number if provided
      if (routingNumber) {
        const routingValidation = this.validateRoutingNumber(routingNumber);
        if (!routingValidation.valid) {
          return {
            valid: false,
            error: `Invalid routing number: ${routingValidation.error}`,
            accountNumber: cleanAccountNumber
          };
        }
      }

      // Check for obviously invalid patterns (all zeros, sequential)
      if (cleanAccountNumber === '0'.repeat(cleanAccountNumber.length)) {
        return {
          valid: false,
          error: 'Account number cannot be all zeros',
          accountNumber: cleanAccountNumber
        };
      }

      // Check for sequential numbers
      const sequential = '0123456789';
      if (sequential.includes(cleanAccountNumber) ||
          cleanAccountNumber.split('').reverse().join('') === sequential) {
        return {
          valid: false,
          error: 'Account number cannot be sequential digits',
          accountNumber: cleanAccountNumber
        };
      }

      return {
        valid: true,
        accountNumber: cleanAccountNumber,
        maskedNumber: this.maskAccountNumber(cleanAccountNumber),
        validationTimestamp: new Date().toISOString()
      };

    } catch (error) {
      return {
        valid: false,
        error: `Validation error: ${error.message}`,
        accountNumber: accountNumber
      };
    }
  }

  /**
   * Validate ABA routing number using checksum algorithm
   * @param {string} routingNumber - 9-digit ABA routing number
   * @returns {Object} Validation result
   */
  validateRoutingNumber(routingNumber) {
    try {
      if (!routingNumber || typeof routingNumber !== 'string') {
        return {
          valid: false,
          error: 'Routing number is required and must be a string'
        };
      }

      // Remove spaces and dashes
      const cleanRouting = routingNumber.replace(/[\s-]/g, '');

      // Must be exactly 9 digits
      if (cleanRouting.length !== 9) {
        return {
          valid: false,
          error: 'Routing number must be exactly 9 digits'
        };
      }

      // Must contain only digits
      if (!/^\d{9}$/.test(cleanRouting)) {
        return {
          valid: false,
          error: 'Routing number must contain only digits'
        };
      }

      // ABA checksum validation
      const digits = cleanRouting.split('').map(Number);
      const checksum = (3 * (digits[0] + digits[3] + digits[6])) +
                      (7 * (digits[1] + digits[4] + digits[7])) +
                      (digits[2] + digits[5] + digits[8]);

      if (checksum % 10 !== 0) {
        return {
          valid: false,
          error: 'Invalid routing number checksum'
        };
      }

      // Check for Federal Reserve routing numbers (common validation)
      const fedDistrict = Number.parseInt(cleanRouting.substring(0, 2));
      if (fedDistrict < 1 || fedDistrict > 12) {
        return {
          valid: false,
          error: 'Invalid Federal Reserve district code'
        };
      }

      return {
        valid: true,
        routingNumber: cleanRouting,
        federalReserveDistrict: fedDistrict,
        checkType: 'ABA',
        validationTimestamp: new Date().toISOString()
      };

    } catch (error) {
      return {
        valid: false,
        error: `Routing number validation error: ${error.message}`
      };
    }
  }

  /**
   * Validate blockchain wallet address
   * @param {string} address - Wallet address to validate
   * @param {string} network - Blockchain network (BTC, ETH, etc.)
   * @returns {Object} Validation result
   */
  validateWalletAddress(address, network = 'ETH') {
    try {
      if (!address || typeof address !== 'string') {
        return {
          valid: false,
          error: 'Wallet address is required and must be a string'
        };
      }

      const cleanAddress = address.trim();

      switch (network.toUpperCase()) {
        case 'BTC':
        case 'BITCOIN':
          // Bitcoin address validation (P2PKH, P2SH, Bech32)
          if (!/^([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})$/.test(cleanAddress)) {
            return {
              valid: false,
              error: 'Invalid Bitcoin address format'
            };
          }
          break;

        case 'ETH':
        case 'ETHEREUM':
          // Ethereum address validation
          if (!/^0x[a-fA-F0-9]{40}$/.test(cleanAddress)) {
            return {
              valid: false,
              error: 'Invalid Ethereum address format'
            };
          }
          break;

        case 'USDC':
        case 'USDT':
          // ERC-20 token addresses (same as ETH)
          if (!/^0x[a-fA-F0-9]{40}$/.test(cleanAddress)) {
            return {
              valid: false,
              error: `Invalid ${network} address format`
            };
          }
          break;

        default:
          // Generic validation for other networks
          if (cleanAddress.length < 20 || cleanAddress.length > 100) {
            return {
              valid: false,
              error: 'Wallet address length is invalid for this network'
            };
          }
      }

      return {
        valid: true,
        address: cleanAddress,
        network: network.toUpperCase(),
        maskedAddress: this.maskWalletAddress(cleanAddress),
        validationTimestamp: new Date().toISOString()
      };

    } catch (error) {
      return {
        valid: false,
        error: `Wallet validation error: ${error.message}`
      };
    }
  }

  /**
   * Validate complete account information
   * @param {Object} accountData - Account data to validate
   * @returns {Object} Comprehensive validation result
   */
  async validateCompleteAccount(accountData) {
    const validationId = crypto.randomBytes(16).toString('hex');
    const timestamp = new Date().toISOString();

    try {
      const results = {
        validationId,
        timestamp,
        overallValid: true,
        accountValidation: null,
        routingValidation: null,
        walletValidation: null,
        balanceValidation: null,
        errors: []
      };

      // Validate account number
      if (accountData.accountNumber) {
        results.accountValidation = this.validateAccountNumber(
          accountData.accountNumber,
          accountData.routingNumber
        );
        if (!results.accountValidation.valid) {
          results.overallValid = false;
          results.errors.push(results.accountValidation.error);
        }
      }

      // Validate routing number
      if (accountData.routingNumber) {
        results.routingValidation = this.validateRoutingNumber(accountData.routingNumber);
        if (!results.routingValidation.valid) {
          results.overallValid = false;
          results.errors.push(results.routingValidation.error);
        }
      }

      // Validate wallet address
      if (accountData.walletAddress) {
        results.walletValidation = this.validateWalletAddress(
          accountData.walletAddress,
          accountData.walletNetwork
        );
        if (!results.walletValidation.valid) {
          results.overallValid = false;
          results.errors.push(results.walletValidation.error);
        }
      }

      // Validate balance (if provided)
      if (accountData.balance !== undefined) {
        results.balanceValidation = this.validateBalance(accountData.balance);
        if (!results.balanceValidation.valid) {
          results.overallValid = false;
          results.errors.push(results.balanceValidation.error);
        }
      }

      // Cache validation result
      this.validatedAccounts.set(validationId, {
        accountData,
        results,
        timestamp
      });

      // Add to history
      this.validationHistory.push({
        validationId,
        accountType: accountData.type || 'unknown',
        overallValid: results.overallValid,
        timestamp
      });

      // Keep only last 1000 validations in history
      if (this.validationHistory.length > 1000) {
        this.validationHistory = this.validationHistory.slice(-1000);
      }

      return results;

    } catch (error) {
      return {
        validationId,
        timestamp,
        overallValid: false,
        errors: [`Validation system error: ${error.message}`]
      };
    }
  }

  /**
   * Validate account balance
   * @param {number} balance - Balance to validate
   * @returns {Object} Balance validation result
   */
  validateBalance(balance) {
    try {
      if (typeof balance !== 'number' || Number.isNaN(balance)) {
        return {
          valid: false,
          error: 'Balance must be a valid number'
        };
      }

      if (balance < -1000000) { // Allow reasonable negative balances
        return {
          valid: false,
          error: 'Balance appears unreasonably negative'
        };
      }

      if (balance > 1000000000) { // Flag extremely high balances
        return {
          valid: false,
          warning: 'Balance appears unusually high - please verify'
        };
      }

      return {
        valid: true,
        balance: balance,
        formattedBalance: new Intl.NumberFormat('en-US', {
          style: 'currency',
          currency: 'USD'
        }).format(balance),
        validationTimestamp: new Date().toISOString()
      };

    } catch (error) {
      return {
        valid: false,
        error: `Balance validation error: ${error.message}`
      };
    }
  }

  /**
   * Get validation history
   * @param {number} limit - Maximum number of records to return
   * @returns {Array} Validation history
   */
  getValidationHistory(limit = 100) {
    return this.validationHistory.at(-limit);
  }

  /**
   * Get validation statistics
   * @returns {Object} Validation statistics
   */
  getValidationStats() {
    const history = this.validationHistory;
    const total = history.length;
    const valid = history.filter(h => h.overallValid).length;
    const invalid = total - valid;

    return {
      totalValidations: total,
      validAccounts: valid,
      invalidAccounts: invalid,
      successRate: total > 0 ? (valid / total * 100).toFixed(2) + '%' : '0%',
      lastValidation: history.length > 0 ? history[history.length - 1].timestamp : null,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Mask account number for security
   * @param {string} accountNumber - Account number to mask
   * @returns {string} Masked account number
   */
  maskAccountNumber(accountNumber) {
    if (!accountNumber || accountNumber.length < 4) return accountNumber;
    return '*'.repeat(accountNumber.length - 4) + accountNumber.slice(-4);
  }

  /**
   * Mask wallet address for security
   * @param {string} address - Wallet address to mask
   * @returns {string} Masked wallet address
   */
  maskWalletAddress(address) {
    if (!address || address.length < 8) return address;
    return address.substring(0, 6) + '*'.repeat(address.length - 10) + address.slice(-4);
  }

  /**
   * Clear validation cache
   */
  clearCache() {
    this.validatedAccounts.clear();
    this.accountCache.clear();
  }

  /**
   * Export validation report
   * @returns {Object} Complete validation report
   */
  exportValidationReport() {
    return {
      stats: this.getValidationStats(),
      history: this.getValidationHistory(500),
      cacheSize: this.validatedAccounts.size,
      exportTimestamp: new Date().toISOString()
    };
  }
}

export default AccountValidationService;
