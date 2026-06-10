/**
 * PRIVATE BANKING SERVICE
 * OSCAR-BROOME-REVENUE System - Proprietary Technology
 * 
 * © 2024 OWLBAN GROUP 🦉 - All Rights Reserved
 * Owned by: King Sachem Yochanan (Oscar Broome)
 * Authority: House of David ✡️, House of Capet ⚜️, House of Logan 🏰
 * 
 * OWNER: THE REVENUE BELONGS TO KING SACHEM YOCHANAN (OSCAR BROOME)
 * ALL FUNDS, ACCOUNTS, AND ASSETS ARE SOLE PROPERTY OF THE OWNER
 * 
 * Manages private banking accounts, assets, and wealth management
 * Provides comprehensive banking operations and asset tracking
 * 
* @typedef {Object} PrivateBankingServiceClass
 * @property {Function} initializeAccounts
 * @property {Function} initializeAssets
 * @property {Function} getPortfolioSummary
 * @property {Function} exportBankingData
 * @property {Function} getAccounts
 * @property {Function} getAccount
 * @property {Function} getAssets
 * @property {Function} getAsset
 * @property {Function} updateAccountBalance
 * @property {Function} updateAssetValue
 * @property {Function} getTransactionHistory
 * @property {Function} getAssetHistory
 * @property {Function} executeBankingOperation
 * @property {Function} formatCurrency
 * @property {Function} getHealthStatus
 * 
 * @typedef {Object} Transaction
 * @property {string} id
 * @property {string} accountId
 * @property {string} type
 * @property {number} amount
 * @property {number} balance
 * @property {string} description
 * @property {string} timestamp
 * 
* @typedef {Object} Account
 * @property {string} id
 * @property {string} name
 * @property {string} type
 * @property {string} currency
 * @property {number} balance
 * @property {number} availableBalance
 * @property {string} accountNumber
 * @property {string} routingNumber
 * @property {string} status
 * @property {number} minimumBalance
 * @property {number} interestRate
 * @property {string} lastTransaction
 * @property {string} createdAt
 * @property {string} updatedAt
 * 
* @typedef {Object} Asset
 * @property {string} id
 * @property {string} name
 * @property {string} type
 * @property {number} value
 * @property {string} currency
 * @property {number} allocation
 * @property {Performance} performance
 * @property {Array<any>|undefined} holdings
 * @property {string} lastUpdated
 * @property {Array<any>} history
 * 
 * @typedef {Object} Performance
 * @property {number} daily
 * @property {number} monthly
 * @property {number} yearly
 */

import crypto from 'crypto';
import logger from '../utils/loggerWrapper.js';

class PrivateBankingService {

  /**
   * Activate liquidity protection mode (NO balance reduction)
   */
  activateLiquidityProtection() {
    logger.warn('🛠️ Liquidity protection ACTIVATED - ALL earned balances PROTECTED');
    
    // Protection without touching balances
    this.protectionLimits = {
      dailyLimit: 1000000000000, // $1T - still huge
      autoFreezeRisky: true,
      requireOverride: true,
    };
    
    logger.info('✅ Protection active - Sovereign override available');
    return this.getPortfolioSummary();
  }

  /**
   * Sovereign override - Bypass all protections
   */
  activateSovereignOverride() {
    logger.info('👑 SOVEREIGN OVERRIDE - King Sachem Yochanan - FULL CONTROL RESTORED');
    this.creditCrisisMode = true;
    this.protectionLimits = null;
    return this.getPortfolioSummary();
  }

/** @type {Array<{id: string, accountId: string, type: string, amount: number, balance: number, description: string, timestamp: string}>} */
constructor() {
    /** @type {Map<string, any>} */
    this.accounts = new Map();
    /** @type {Map<string, any>} */
    this.assets = new Map();
    /** @type {Array<any>} */
    this.transactions = [];
    /** @type {Map<string, any[]>} */
    this.assetHistory = new Map();
    /** @type {Map<string, any>} */
    this.portfolioAnalytics = new Map();
    /** @type {Map<string, any>} */
    this.riskMetrics = new Map();
this.creditCrisisMode = false;
    this.protectionLimits = null;
    this.sovereignOverrideActive = false;
  }

/**
   * Initialize private banking accounts
   * @param {Array<Account>} accountData - Array of account configurations
   */
initializeAccounts(accountData = []) {
    // Default accounts if none provided
    const defaultAccounts = [
      {
        id: 'primary-checking',
        name: 'Primary Checking Account',
        type: 'checking',
        currency: 'USD',
        balance: 2500000.0,
        availableBalance: 2400000.0,
        accountNumber: '****1234',
        routingNumber: '021000021', // JPMorgan routing
        status: 'active',
        minimumBalance: 1000.0,
        interestRate: 0.001,
        lastTransaction: new Date(Date.now() - 86400000).toISOString(),
      },
      {
        id: 'investment-account',
        name: 'Investment Portfolio',
        type: 'investment',
        currency: 'USD',
        balance: 15000000.0,
        availableBalance: 14800000.0,
        accountNumber: '****5678',
        routingNumber: '021000021',
        status: 'active',
        minimumBalance: 0,
        interestRate: 0.045,
        lastTransaction: new Date(Date.now() - 43200000).toISOString(),
      },
      {
        id: 'private-reserve',
        name: 'Private Banking Reserve',
        type: 'savings',
        currency: 'USD',
        balance: 50000000.0,
        availableBalance: 49500000.0,
        accountNumber: '****9012',
        routingNumber: '021000021',
        status: 'active',
        minimumBalance: 50000.0,
        interestRate: 0.025,
        lastTransaction: new Date(Date.now() - 21600000).toISOString(),
      },
    ];

    const accountsToInitialize =
      accountData.length > 0 ? accountData : defaultAccounts;

    accountsToInitialize.forEach((account) => {
      this.accounts.set(account.id, {
        ...account,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    });

    logger.info(
      `Initialized ${accountsToInitialize.length} private banking accounts`
    );
  }

/**
   * Initialize asset portfolio
   * @param {Array<Asset>} assetData - Array of asset configurations
   */
initializeAssets(assetData = []) {
    // Default assets if none provided
    const defaultAssets = [
      {
        id: 'stocks-equities',
        name: 'Stocks & Equities',
        type: 'equity',
        value: 25000000.0,
        currency: 'USD',
        allocation: 0.35,
        performance: {
          daily: 0.012,
          monthly: 0.045,
          yearly: 0.128,
        },
        holdings: [
          { symbol: 'AAPL', shares: 50000, value: 7500000 },
          { symbol: 'MSFT', shares: 30000, value: 6000000 },
          { symbol: 'GOOGL', shares: 15000, value: 3000000 },
        ],
      },
      {
        id: 'fixed-income',
        name: 'Fixed Income Securities',
        type: 'bonds',
        value: 20000000.0,
        currency: 'USD',
        allocation: 0.28,
        performance: {
          daily: 0.003,
          monthly: 0.012,
          yearly: 0.042,
        },
        holdings: [
          { name: 'US Treasury 10Y', value: 10000000, yield: 0.045 },
          { name: 'Corporate Bonds AAA', value: 10000000, yield: 0.038 },
        ],
      },
      {
        id: 'alternative-investments',
        name: 'Alternative Investments',
        type: 'alternative',
        value: 15000000.0,
        currency: 'USD',
        allocation: 0.21,
        performance: {
          daily: 0.008,
          monthly: 0.032,
          yearly: 0.089,
        },
        holdings: [
          { name: 'Private Equity Fund', value: 8000000 },
          { name: 'Hedge Fund', value: 5000000 },
          { name: 'Real Estate', value: 2000000 },
        ],
      },
      {
        id: 'cash-reserves',
        name: 'Cash & Cash Equivalents',
        type: 'cash',
        value: 10000000.0,
        currency: 'USD',
        allocation: 0.14,
        performance: {
          daily: 0.001,
          monthly: 0.003,
          yearly: 0.025,
        },
      },
      {
        id: 'crypto-assets',
        name: 'Cryptocurrency Assets',
        type: 'crypto',
        value: 2000000.0,
        currency: 'USD',
        allocation: 0.02,
        performance: {
          daily: -0.025,
          monthly: 0.156,
          yearly: 0.234,
        },
        holdings: [
          { symbol: 'BTC', amount: 25, value: 1250000 },
          { symbol: 'ETH', amount: 500, value: 750000 },
        ],
      },
    ];

    const assetsToInitialize = assetData.length > 0 ? assetData : defaultAssets;

    assetsToInitialize.forEach((asset) => {
      this.assets.set(asset.id, {
        ...asset,
        lastUpdated: new Date().toISOString(),
        history: [],
      });

      // Initialize asset history
      this.assetHistory.set(asset.id, []);
    });

    logger.info(`Initialized ${assetsToInitialize.length} asset classes`);
  }

/**
   * Get all banking accounts
   * @returns {Array<Object>} Array of account objects
   */
getAccounts() {
    return [...this.accounts.values()].map((/** @type {any} */ account) => ({
      ...account,
      balance: this.formatCurrency(account.balance, account.currency),
      availableBalance: this.formatCurrency(
        account.availableBalance,
        account.currency
      ),
    }));
  }

  /**
   * Get account by ID
   * @param {string} accountId - Account ID
   * @returns {Object|null} Account object or null
   */
  getAccount(accountId) {
    const account = this.accounts.get(accountId);
    if (!account) return null;

    return {
      ...account,
      balance: this.formatCurrency(account.balance, account.currency),
      availableBalance: this.formatCurrency(
        account.availableBalance,
        account.currency
      ),
    };
  }

/**
   * Get all assets
   * @returns {Array<Object>} Array of asset objects
   */
getAssets() {
    return [...this.assets.values()].map((/** @type {any} */ asset) => ({
      ...asset,
      value: this.formatCurrency(asset.value, asset.currency),
      allocation: (asset.allocation * 100).toFixed(2) + '%',
    }));
  }

  /**
   * Get asset by ID
   * @param {string} assetId - Asset ID
   * @returns {Object|null} Asset object or null
   */
  getAsset(assetId) {
    const asset = this.assets.get(assetId);
    if (!asset) return null;

    return {
      ...asset,
      value: this.formatCurrency(asset.value, asset.currency),
      allocation: (asset.allocation * 100).toFixed(2) + '%',
    };
  }

/**
 * Update account balance
 * @param {string} accountId - Account ID
 * @param {number} newBalance - New balance
 * @param {string} transactionType - Type of transaction
 * @param {string} description - Transaction description
 * @returns {{success: false, error: string} | {success: true, account: any, transaction: any, oldBalance: string, newBalance: string}} Update result
 */
  updateAccountBalance(
    accountId,
    newBalance,
    transactionType = 'adjustment',
    description = ''
  ) {
    const account = this.accounts.get(accountId);
    if (!account) {
      return { success: false, error: 'Account not found' };
    }

    const oldBalance = account.balance;
    const difference = newBalance - oldBalance;

    account.balance = newBalance;
    account.availableBalance = Math.max(
      0,
      newBalance - (account.minimumBalance || 0)
    );
    account.updatedAt = new Date().toISOString();
    account.lastTransaction = new Date().toISOString();

    // Record transaction
    const transaction = {
      id: crypto.randomBytes(16).toString('hex'),
      accountId,
      type: transactionType,
      amount: difference,
      balance: newBalance,
      description: description || `${transactionType} adjustment`,
      timestamp: new Date().toISOString(),
    };

    this.transactions.push(transaction);

    // Keep only last 1000 transactions
    if (this.transactions.length > 1000) {
      this.transactions = this.transactions.slice(-1000);
    }

    return {
      success: true,
      account: this.getAccount(accountId),
      transaction,
      oldBalance: this.formatCurrency(oldBalance, account.currency),
      newBalance: this.formatCurrency(newBalance, account.currency),
    };
  }

/**
   * Update asset value
   * @param {string} assetId - Asset ID
   * @param {number} newValue - New asset value
   * @param {string} reason - Reason for update
   * @returns {{success: false, error: string} | {success: true, asset: any, oldValue: string, newValue: string, change: string, changePercent: string}} Update result
   */
  updateAssetValue(assetId, newValue, reason = 'valuation') {
    const asset = this.assets.get(assetId);
    if (!asset) {
      return { success: false, error: 'Asset not found' };
    }

    const oldValue = asset.value;
    const change = newValue - oldValue;
    const changePercent = oldValue > 0 ? (change / oldValue) * 100 : 0;

    asset.value = newValue;
    asset.lastUpdated = new Date().toISOString();

    // Update performance based on change
    if (reason === 'market') {
      asset.performance.daily = changePercent / 100;
    }

    // Record in history
    const historyEntry = {
      timestamp: new Date().toISOString(),
      value: newValue,
      change: change,
      changePercent: changePercent,
      reason: reason,
    };

    const history = this.assetHistory.get(assetId) || [];
    history.push(historyEntry);

    // Keep only last 1000 entries per asset
    if (history.length > 1000) {
      this.assetHistory.set(assetId, history.slice(-1000));
    } else {
      this.assetHistory.set(assetId, history);
    }

    return {
      success: true,
      asset: this.getAsset(assetId),
      oldValue: this.formatCurrency(oldValue, asset.currency),
      newValue: this.formatCurrency(newValue, asset.currency),
      change: this.formatCurrency(change, asset.currency),
      changePercent: changePercent.toFixed(2) + '%',
    };
  }

/**
   * Get portfolio summary
   * @returns {{totalPortfolioValue: string, totalAccountBalance: string, totalAssetValue: string, assetAllocation: object, performance: {totalReturn: string, numberOfAccounts: number, numberOfAssets: number}, lastUpdated: string}} Portfolio summary
   */
getPortfolioSummary() {
    const accounts = Array.from(this.accounts.values());
    const assets = Array.from(this.assets.values());

    const totalAccountBalance = accounts.reduce(
      (sum, acc) => sum + acc.balance,
      0
    );
    const totalAssetValue = assets.reduce((sum, asset) => sum + asset.value, 0);
    const totalPortfolioValue = totalAccountBalance + totalAssetValue;

    // Calculate asset allocation
    /** @type {Object.<string, any>} */
    const assetAllocation = {};
    assets.forEach((asset) => {
      const key = asset.name;
      assetAllocation[key] = {
        value: asset.value,
        percentage:
          totalAssetValue > 0 ? (asset.value / totalAssetValue) * 100 : 0,
        performance: asset.performance,
      };
    });

    // Calculate performance metrics
    const totalReturn = assets.reduce((sum, asset) => {
      return sum + (asset.performance?.yearly || 0) * asset.allocation;
    }, 0);

    return {
      totalPortfolioValue: this.formatCurrency(totalPortfolioValue, 'USD'),
      totalAccountBalance: this.formatCurrency(totalAccountBalance, 'USD'),
      totalAssetValue: this.formatCurrency(totalAssetValue, 'USD'),
      assetAllocation,
      performance: {
        totalReturn: (totalReturn * 100).toFixed(2) + '%',
        numberOfAccounts: accounts.length,
        numberOfAssets: assets.length,
      },
      lastUpdated: new Date().toISOString(),
    };
  }

/**
   * Get transaction history
   * @param {string|null} accountId - Optional account ID filter
   * @param {number} limit - Maximum number of transactions
   * @returns {Array<any>} Transaction history
   */
  getTransactionHistory(accountId = null, limit = 100) {
    let transactions = this.transactions;

    if (accountId) {
      transactions = transactions.filter((tx) => tx.accountId === accountId);
    }

    return transactions
      .slice(-limit)
      .reverse()
      .map((tx) => ({
        ...tx,
        amount: this.formatCurrency(tx.amount, 'USD'),
        balance: this.formatCurrency(tx.balance, 'USD'),
      }));
  }

/**
   * Get asset performance history
   * @param {string} assetId - Asset ID
   * @param {number} days - Number of days of history
   * @returns {Array<any>} Asset performance history
   */
  getAssetHistory(assetId, days = 30) {
    const history = this.assetHistory.get(assetId) || [];
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    return history
      .filter((entry) => new Date(entry.timestamp) >= cutoffDate)
      .map((entry) => ({
        ...entry,
        value: this.formatCurrency(entry.value, 'USD'),
        change: this.formatCurrency(entry.change, 'USD'),
      }));
  }

/**
   * Execute banking operation
   * @param {string} operation - Operation type
   * @param {string} accountId - Account ID
   * @param {Object} params - Operation parameters
   * @returns {Promise<Object>} Operation result
   */
async executeBankingOperation(operation, accountId, params = {}) {
    // SOVEREIGN OWNER BYPASS: King Sachem Yochanan's accounts can NEVER be frozen
    // The owner has absolute control - no freeze can ever block owner access
    const account = this.accounts.get(accountId);
    if (!account) {
      return { success: false, error: 'Account not found' };
    }
    
    // Check if this is owner's account - never allow freeze to block sovereign
    const isOwnerAccount = account.owner === 'king-sachem-yochanan' || 
                          account.owner === 'oscar-broome' ||
                          account.id.includes('primary-checking') ||
                          account.id.includes('private-reserve') ||
                          account.id.includes('investment');
    
// Allow operations on any account if it's owner's account, regardless of frozen status
    if (isOwnerAccount || this.sovereignOverrideActive) {
      // SOVEREIGN HAS FULL ACCESS - accounts can NEVER be truly frozen from sovereign
      try {
      switch (operation) {
        case 'transfer':
          return this.executeTransfer(accountId, params);

        case 'deposit':
          return this.executeDeposit(accountId, params);

        case 'withdrawal':
          return this.executeWithdrawal(accountId, params);



        case 'close':
          return this.closeAccount(accountId, params);

        default:
          return { success: false, error: 'Unknown operation' };
      }
} catch (error) {
      return { success: false, error: `Operation failed: ${error.message}` };
    }
    }
    
    // Default return for non-owner accounts
    return { success: false, error: 'Operation not permitted' };
  }

  /**
   * Execute fund transfer
   * @param {string} accountId - From account ID
   * @param {Object} params - Transfer params with toAccountId, amount, description
   * @returns {Object} Transfer result
   */
  executeTransfer(
    /** @type {string} */ accountId, 
    /** @type {{toAccountId?: string, amount?: number, description?: string}} */ params
  ) {
    const { toAccountId, amount, description } = params;

    if (!toAccountId || !amount) {
      return { success: false, error: 'To account and amount are required' };
    }

    const fromAccount = this.accounts.get(accountId);
    const toAccount = this.accounts.get(toAccountId);

    if (!fromAccount || !toAccount) {
      return { success: false, error: 'Destination account not found' };
    }

    if (fromAccount.balance < amount) {
      return { success: false, error: 'Insufficient funds' };
    }

    // Debit from account
    this.updateAccountBalance(
      accountId,
      fromAccount.balance - amount,
      'transfer',
      `Transfer to ${toAccount.name}: ${description || ''}`
    );

    // Credit to account
    this.updateAccountBalance(
      toAccountId,
      toAccount.balance + amount,
      'transfer',
      `Transfer from ${fromAccount.name}: ${description || ''}`
    );

    return {
      success: true,
      message: `Transferred ${this.formatCurrency(amount, 'USD')} from ${fromAccount.name} to ${toAccount.name}`,
      fromAccount: accountId,
      toAccount: toAccountId,
      amount: this.formatCurrency(amount, 'USD'),
    };
  }

/**
   * Execute deposit
   * @param {string} accountId - Account ID
   * @param {Object} params - Deposit params with amount, description
   * @returns {Object} Deposit result
   */
  executeDeposit(
    /** @type {string} */ accountId,
    /** @type {{amount?: number, description?: string}} */ params
  ) {
    const { amount, description } = params;

    if (!amount || amount <= 0) {
      return { success: false, error: 'Valid amount is required' };
    }

    const account = this.accounts.get(accountId);
    if (!account) {
      return { success: false, error: 'Account not found' };
    }
    const newBalance = account.balance + amount;

    this.updateAccountBalance(
      accountId,
      newBalance,
      'deposit',
      description || 'Cash deposit'
    );

    return {
      success: true,
      message: `Deposited ${this.formatCurrency(amount, 'USD')} to ${account.name}`,
      account: accountId,
      amount: this.formatCurrency(amount, 'USD'),
      newBalance: this.formatCurrency(newBalance, 'USD'),
    };
  }

  /**
   * Execute withdrawal
   * @param {string} accountId - Account ID
   * @param {Object} params - Withdrawal params with amount, description
   * @returns {Object} Withdrawal result
   */
  executeWithdrawal(
    /** @type {string} */ accountId,
    /** @type {{amount?: number, description?: string}} */ params
  ) {
    const { amount, description } = params;

    if (!amount || amount <= 0) {
      return { success: false, error: 'Valid amount is required' };
    }

    const account = this.accounts.get(accountId);
    if (!account) {
      return { success: false, error: 'Account not found' };
    }

    if (account.balance < amount) {
      return { success: false, error: 'Insufficient funds' };
    }

    const newBalance = account.balance - amount;

    this.updateAccountBalance(
      accountId,
      newBalance,
      'withdrawal',
      description || 'Cash withdrawal'
    );

    return {
      success: true,
      message: `Withdrew ${this.formatCurrency(amount, 'USD')} from ${account.name}`,
      account: accountId,
      amount: this.formatCurrency(amount, 'USD'),
      newBalance: this.formatCurrency(newBalance, 'USD'),
    };
  }

/**
   * Pay bill directly from owner funds - FULL ACCESS
   * Owner can use ANY account balance for bill payment
   * @param {number} billAmount - Amount to pay
   * @param {string} billDescription - Description
   * @param {string} fromAccountId - Source account ID
   * @returns {Object} Payment result
   */
  payBill(
    /** @type {number} */ billAmount,
    /** @type {string} */ billDescription,
    fromAccountId = 'primary-checking'
  ) {
    const account = this.accounts.get(fromAccountId);
    if (!account) {
      // Try other accounts
      const accounts = Array.from(this.accounts.values());
      for (const acc of accounts) {
        if (acc.balance >= billAmount && acc.status === 'active') {
          return this.executeWithdrawal(acc.id, { 
            amount: billAmount, 
            description: billDescription || 'Bill payment' 
          });
        }
      }
      return { success: false, error: 'Insufficient funds across all accounts' };
    }
    
    if (account.balance < billAmount) {
      // Check other accounts
      const accounts = Array.from(this.accounts.values());
      for (const acc of accounts) {
        if (acc.balance >= billAmount && acc.status === 'active') {
          return this.executeWithdrawal(acc.id, { 
            amount: billAmount, 
            description: billDescription || 'Bill payment' 
          });
        }
      }
      return { success: false, error: 'Insufficient funds' };
    }
    
    return this.executeWithdrawal(fromAccountId, { 
      amount: billAmount, 
      description: billDescription || 'Bill payment' 
    });
  }

/**
   * Get any account balance - Owner access
   * @param {string|null} accountId - Optional account ID
   * @returns {number} Account balance
   */
  getOwnerBalance(/** @type {string|null} */ accountId = null) {
    if (accountId) {
      const account = this.accounts.get(accountId);
      if (!account) {
        return 0;
      }
      return account.balance;
    }
    // Get total across all accounts
    return Array.from(this.accounts.values()).reduce((sum, acc) => sum + acc.balance, 0);
  }

/**
   * Close account
   * @param {string} accountId - Account ID
   * @returns {Object} Close result
   */
closeAccount(
    /** @type {string} */ accountId,
    /** @type {Object} */ _params
  ) {
    const account = this.accounts.get(accountId);
    if (!account) {
      return { success: false, error: 'Account not found' };
    }

    if (account.balance > 0) {
      return {
        success: false,
        error: 'Cannot close account with positive balance',
      };
    }

    account.status = 'closed';
    account.updatedAt = new Date().toISOString();

    return {
      success: true,
      message: `Account ${account.name} has been closed`,
      account: accountId,
      status: 'closed',
    };
  }

  /**
   * Format currency value
   * @param {number} value - Numeric value
   * @param {string} currency - Currency code
   * @returns {string} Formatted currency string
   */
  formatCurrency(value, currency = 'USD') {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency,
    }).format(value);
  }

/**
   * Get banking service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    const lastTx = this.transactions.length > 0 
      ? this.transactions[this.transactions.length - 1].timestamp 
      : undefined;
    return {
      status: 'healthy',
      accounts: this.accounts.size,
      assets: this.assets.size,
      transactions: this.transactions.length,
      lastTransaction: lastTx || '',
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Export banking data
   * @returns {Object} Complete banking data export
   */
  exportBankingData() {
    return {
      accounts: Array.from(this.accounts.values()),
      assets: Array.from(this.assets.values()),
      transactions: this.transactions,
      assetHistory: Object.fromEntries(this.assetHistory),
      portfolioSummary: this.getPortfolioSummary(),
      exportTimestamp: new Date().toISOString(),
    };
  }
}

export default PrivateBankingService;
