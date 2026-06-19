/**
 * @ts-nocheck
 * PERSONAL ACCOUNTS SERVICE
 * OSCAR-BROOME-REVENUE System - Proprietary Technology
 * 
 * © 2024 OWLBAN GROUP 🦉 - All Rights Reserved
 * Owned by: King Sachem Yochanan (Oscar Broome)
 * Authority: House of David ✡️, House of Capet ⚜️, House of Logan 🏰
 * 
 * PROTECTED BY CUSTOM ENCRYPTION - DO NOT SHARE
 * This module manages personal accounts, online cards, and banking connections.
 */

import crypto from 'crypto';
import logger from '../utils/loggerWrapper.js';
import plaidService from './plaidService.js';
import PrivateBankingService from './privateBankingService.js';
import AccountValidationService from './accountValidationService.js';

/**
 * @typedef {Object} BankAccount
 * @property {string} id
 * @property {string} institutionId
 * @property {string} institutionName
 * @property {string} accountNumber
 * @property {string} routingNumber
 * @property {string} accountType - checking, savings, investment
 * @property {string} status - active, pending, closed
 * @property {number} balance
 * @property {number} [availableBalance]
 * @property {string} [plaidAccessToken]
 * @property {string} [plaidItemId]
 * @property {string} mask
 * @property {string} name
 * @property {string} [linkedAt]
 * @property {string} [closedAt]
 */

/**
 * @typedef {Object} PlaidAccountData
 * @property {string} accountId
 * @property {string} [institutionName]
 * @property {string} [accountNumber]
 * @property {string} [routingNumber]
 * @property {string} [accountType]
 */

/**
 * @typedef {Object} Card
 * @property {string} id
 * @property {string} cardNumber
 * @property {string} maskedNumber
 * @property {string} cardType - debit, credit, virtual
 * @property {string} status - active, blocked, expired
 * @property {string} expiryDate
 * @property {string} cvv
 * @property {number} balance
 * @property {number} availableBalance
 * @property {number} limit
 * @property {string} network - Visa, Mastercard, Amex
 * @property {string} issueDate
 * @property {string} lastTransaction
 * @property {string} blockedAt
 * @property {string} unblockedAt
 * @property {Transaction[]} transactions
 */

/**
 * @typedef {Object} Transaction
 * @property {string} id
 * @property {string} [accountId]
 * @property {string} [cardId]
 * @property {number} [amount]
 * @property {string} [description]
 * @property {string} [timestamp]
 * @property {string} [status]
 * @property {string} [fromAccountId]
 * @property {string} [toAccountId]
 */

/**
 * @typedef {Object} ValidationResult
 * @property {boolean} valid
 * @property {string} [error]
 */

/**
 * @typedef {Object} CardData
 * @property {string} [id]
 * @property {string} [cardType]
 * @property {string} [network]
 * @property {string} [name]
 * @property {string} [expiryDate]
 * @property {number} [limit]
 * @property {string} [status]
 * @property {boolean} [isVirtual]
 * @property {string} [cardholderName]
 */

/**
 * @typedef {Object} LinkAccountData
 * @property {string} accountId
 * @property {string} [institutionName]
 * @property {string} [accountNumber]
 * @property {string} [routingNumber]
 * @property {string} [accountType]
 */

/**
 * @typedef {Object} TransactionOptions
 * @property {string} [accountId]
 * @property {string} [cardId]
 * @property {number} [limit]
 */

class PersonalAccountsService {
  constructor() {
    /** @type {PrivateBankingService} */
    this.privateBankingService = new PrivateBankingService();
    /** @type {AccountValidationService} */
    this.accountValidationService = new AccountValidationService();
    /** @type {Map<string, BankAccount>} */
    this.bankAccounts = new Map();
    /** @type {Map<string, Card>} */
    this.cards = new Map();
    /** @type {Transaction[]} */
    this.transactions = [];
    /** @type {Map<string, string>} */
    this.linkedAccounts = new Map();
    
    // Initialize default private banking accounts
    this.initializeDefaultAccounts();
    this.initializeDefaultCards();
  }

  /**
   * Initialize default private banking accounts
   */
  initializeDefaultAccounts() {
    // @ts-ignore - method exists but not in type defs
    this.privateBankingService.initializeAccounts();
    // @ts-ignore - method exists but not in type defs
    this.privateBankingService.initializeAssets();
    
    logger.info('✓ Personal accounts initialized');
  }

  /**
   * Initialize default cards
   */
  initializeDefaultCards() {
    const defaultCards = [
      {
        id: 'primary-visa-debit',
        cardType: 'debit',
        network: 'Visa',
        name: 'Oscar Broome Primary Debit',
        expiryDate: '12/2028',
        limit: 50000,
        status: 'active',
        isVirtual: false,
        cardholderName: 'King Sachem Yochanan',
      },
      {
        id: 'virtual-mastercard',
        cardType: 'debit',
        network: 'Mastercard',
        name: 'Oscar Broome Virtual',
        expiryDate: '06/2027',
        limit: 10000,
        status: 'active',
        isVirtual: true,
        cardholderName: 'King Sachem Yochanan',
      },
      {
        id: 'reserve-amex',
        cardType: 'credit',
        network: 'Amex',
        name: 'Oscar Broome Reserve',
        expiryDate: '09/2029',
        limit: 100000,
        status: 'active',
        isVirtual: false,
        cardholderName: 'King Sachem Yochanan',
      },
    ];

    defaultCards.forEach((card) => {
      const fullCard = this._createCardObject(card);
      this.cards.set(card.id, fullCard);
    });

    logger.info(`✓ Initialized ${defaultCards.length} cards`);
  }

  /**
   * Create full card object with generated details
   */
  _createCardObject(cardData) {
    const now = new Date();
    
    // Generate card number based on network
    let cardNumber;
    switch (cardData.network) {
      case 'Visa':
        cardNumber = '4' + this._generateCardNumber(15);
        break;
      case 'Mastercard':
        cardNumber = '5' + this._generateCardNumber(15);
        break;
      case 'Amex':
        cardNumber = '37' + this._generateCardNumber(13);
        break;
      default:
        cardNumber = '4' + this._generateCardNumber(15);
    }

    // Generate CVV
    const cvv = this._generateCVV();

    return {
      ...cardData,
      cardNumber: cardNumber,
      maskedNumber: this._maskCardNumber(cardNumber),
      cvv: cvv,
      issueDate: now.toISOString(),
      balance: 0,
      availableBalance: cardData.limit || 0,
      lastTransaction: null,
      transactions: [],
    };
  }

  /**
   * Generate random card number digits
   */
  _generateCardNumber(length) {
    let number = '';
    for (let i = 0; i < length; i++) {
      number += Math.floor(Math.random() * 10);
    }
    return number;
  }

  /**
   * Generate CVV
   */
  _generateCVV() {
    return Math.floor(100 + Math.random() * 900).toString();
  }

  /**
   * Mask card number for display
   */
  _maskCardNumber(cardNumber) {
    if (!cardNumber || cardNumber.length < 4) return '****';
    return '*'.repeat(cardNumber.length - 4) + cardNumber.slice(-4);
  }

  /**
   * Link a bank account via Plaid
   */
  async linkBankAccount(publicToken, institutionId, accountData) {
    try {
      // Exchange public token for access token
      const exchangeResult = await plaidService.exchangePublicToken(publicToken);
      
      // Get account information
      const accounts = await plaidService.getAccounts(exchangeResult.access_token);
      
      // Find the specified account
      const linkedAccount = accounts.find(
        (acc) => acc.account_id === accountData.accountId
      );

      if (!linkedAccount) {
        return { success: false, error: 'Account not found' };
      }

      // Get auth information for account and routing numbers
      const authInfo = await plaidService.getAuth(exchangeResult.access_token);
      const accountNumbers = authInfo.numbers?.ach?.find(
        (num) => num.account_id === linkedAccount.account_id
      );

      // Validate the account
      const validation = this.accountValidationService.validateAccountNumber(
        accountNumbers?.account || accountData.accountNumber,
        accountNumbers?.routing || accountData.routingNumber
      );

      if (!validation.valid) {
        return { success: false, error: validation.error };
      }

      // Create bank account record
      const bankAccount = {
        id: crypto.randomBytes(16).toString('hex'),
        institutionId: institutionId,
        institutionName: accountData.institutionName || 'Bank',
        accountNumber: accountNumbers?.account || accountData.accountNumber,
        routingNumber: accountNumbers?.routing || accountData.routingNumber,
        accountType: linkedAccount.subtype || accountData.accountType || 'checking',
        status: 'active',
        balance: linkedAccount.balances?.current || 0,
        availableBalance: linkedAccount.balances?.available || 0,
        plaidAccessToken: exchangeResult.access_token,
        plaidItemId: exchangeResult.item_id,
        mask: linkedAccount.mask,
        name: linkedAccount.name,
        linkedAt: new Date().toISOString(),
      };

      this.bankAccounts.set(bankAccount.id, bankAccount);
      this.linkedAccounts.set(exchangeResult.access_token, bankAccount.id);

      logger.info(`✓ Bank account linked: ${bankAccount.name}`);
      return { success: true, bankAccount };
    } catch (error) {
      logger.error('Bank account linking failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Get all linked bank accounts
   */
  getBankAccounts() {
    const accounts = Array.from(this.bankAccounts.values());
    return accounts.map((account) => ({
      ...account,
      accountNumber: this._maskAccountNumber(account.accountNumber),
    }));
  }

  /**
   * Get bank account by ID
   */
  getBankAccount(accountId) {
    const account = this.bankAccounts.get(accountId);
    if (!account) return null;

    return {
      ...account,
      accountNumber: this._maskAccountNumber(account.accountNumber),
    };
  }

  /**
   * Get card by ID
   */
  getCard(cardId) {
    const card = this.cards.get(cardId);
    if (!card) return null;

    return {
      ...card,
      cardNumber: this._maskCardNumber(card.cardNumber),
      cvv: '***',
    };
  }

  /**
   * Get all cards
   */
  getCards() {
    return Array.from(this.cards.values()).map((card) => ({
      ...card,
      cardNumber: this._maskCardNumber(card.cardNumber),
      cvv: '***',
    }));
  }

/**
   * Create a new virtual card
   * @returns {{ success: boolean; card?: any; error?: string }}
   */
  createVirtualCard(cardData) {
    const cardId = `virtual-${crypto.randomBytes(8).toString('hex')}`;
    
    const newCard = {
      id: cardId,
      cardType: 'debit',
      network: cardData.network || 'Visa',
      name: cardData.name || 'Virtual Card',
      expiryDate: cardData.expiryDate || '12/2027',
      limit: cardData.limit || 5000,
      status: 'active',
      isVirtual: true,
      cardholderName: cardData.cardholderName || 'King Sachem Yochanan',
    };

    const fullCard = this._createCardObject(newCard);
    this.cards.set(cardId, fullCard);

    logger.info(`✓ Virtual card created: ${cardId}`);
    return { success: true, card: this.getCard(cardId) };
  }

  /**
   * Block a card
   */
  blockCard(cardId) {
    const card = this.cards.get(cardId);
    if (!card) {
      return { success: false, error: 'Card not found' };
    }

    card.status = 'blocked';
    card.blockedAt = new Date().toISOString();
    this.cards.set(cardId, card);

    logger.info(`✓ Card blocked: ${cardId}`);
    return { success: true };
  }

  /**
   * Unblock a card
   */
  unblockCard(cardId) {
    const card = this.cards.get(cardId);
    if (!card) {
      return { success: false, error: 'Card not found' };
    }

    card.status = 'active';
    card.unblockedAt = new Date().toISOString();
    this.cards.set(cardId, card);

    logger.info(`✓ Card unblocked: ${cardId}`);
    return { success: true };
  }

  /**
   * Get private banking summary
   */
  getBankingSummary() {
    return this.privateBankingService.getPortfolioSummary();
  }

  /**
   * Get transaction history
   */
  getTransactionHistory(options = {}) {
    const { accountId, cardId, limit = 50 } = options;
    
    let transactions = this.transactions;

    if (accountId) {
      transactions = transactions.filter((tx) => tx.accountId === accountId);
    }

    if (cardId) {
      transactions = transactions.filter((tx) => tx.cardId === cardId);
    }

    return transactions.slice(-limit).reverse();
  }

  /**
   * Process a card transaction
   */
  processCardTransaction(cardId, amount, description) {
    const card = this.cards.get(cardId);
    if (!card) {
      return { success: false, error: 'Card not found' };
    }

    if (card.status !== 'active') {
      return { success: false, error: 'Card is not active' };
    }

    if (amount > card.availableBalance) {
      return { success: false, error: 'Insufficient funds' };
    }

    const transaction = {
      id: crypto.randomBytes(16).toString('hex'),
      cardId: cardId,
      amount: amount,
      description: description,
      timestamp: new Date().toISOString(),
      status: 'completed',
    };

    card.balance += amount;
    card.availableBalance -= amount;
    card.lastTransaction = transaction.timestamp;
    card.transactions.push(transaction);
    this.cards.set(cardId, card);

    this.transactions.push(transaction);

    logger.info(`✓ Card transaction processed: $${amount}`);
    return { success: true, transaction };
  }

  /**
   * Get account balance
   */
  async getAccountBalance(accountId) {
    const account = this.bankAccounts.get(accountId);
    if (!account) {
      return { success: false, error: 'Account not found' };
    }

    try {
      // Get fresh balance from Plaid
      const balances = await plaidService.getBalances(account.plaidAccessToken);
      const accountBalance = balances.find(
        (bal) => bal.account_id === account.plaidItemId
      );

      if (accountBalance) {
        account.balance = accountBalance.balances?.current || 0;
        account.availableBalance = accountBalance.balances?.available || 0;
        this.bankAccounts.set(accountId, account);
      }

      return {
        success: true,
        balance: account.balance,
        availableBalance: account.availableBalance,
      };
    } catch (error) {
      return {
        success: true,
        balance: account.balance,
        availableBalance: account.availableBalance,
      };
    }
  }

  /**
   * Transfer between accounts
   */
  async transferFunds(fromAccountId, toAccountId, amount, description) {
    const fromAccount = this.bankAccounts.get(fromAccountId);
    const toAccount = this.bankAccounts.get(toAccountId);

    if (!fromAccount || !toAccount) {
      return { success: false, error: 'Account not found' };
    }

    if (fromAccount.balance < amount) {
      return { success: false, error: 'Insufficient funds' };
    }

    // Update balances
    fromAccount.balance -= amount;
    toAccount.balance += amount;

    this.bankAccounts.set(fromAccountId, fromAccount);
    this.bankAccounts.set(toAccountId, toAccount);

    // Record transaction
    const transaction = {
      id: crypto.randomBytes(16).toString('hex'),
      fromAccountId,
      toAccountId,
      amount,
      description,
      timestamp: new Date().toISOString(),
    };

    this.transactions.push(transaction);

    logger.info(`✓ Transfer completed: $${amount}`);
    return { success: true, transaction };
  }

  /**
   * Unlink bank account
   */
  async unlinkBankAccount(accountId) {
    const account = this.bankAccounts.get(accountId);
    if (!account) {
      return { success: false, error: 'Account not found' };
    }

    try {
      // Remove Plaid item
      await plaidService.removeItem(account.plaidAccessToken);
    } catch (error) {
      logger.warn('Plaid item removal failed:', error.message);
    }

    account.status = 'closed';
    account.closedAt = new Date().toISOString();
    this.bankAccounts.set(accountId, account);

    logger.info(`✓ Bank account unlinked: ${accountId}`);
    return { success: true };
  }

  /**
   * Mask account number
   */
  _maskAccountNumber(accountNumber) {
    if (!accountNumber || accountNumber.length < 4) return '****';
    return '*'.repeat(accountNumber.length - 4) + accountNumber.slice(-4);
  }

  /**
   * Export all account data
   */
  exportAccountData() {
    return {
      bankAccounts: this.getBankAccounts(),
      cards: this.getCards(),
      privateBanking: this.privateBankingService.exportBankingData(),
      transactions: this.transactions,
      exportTimestamp: new Date().toISOString(),
    };
  }

  /**
   * Get health status
   */
  getHealthStatus() {
    return {
      status: 'healthy',
      bankAccounts: this.bankAccounts.size,
      cards: this.cards.size,
      linkedAccounts: this.linkedAccounts.size,
      transactions: this.transactions.length,
      timestamp: new Date().toISOString(),
    };
  }
}

export default PersonalAccountsService;
