/**
 * PRIVATE BANKING ROUTES
 * OSCAR-BROOME-REVENUE System - Proprietary Technology
 * 
 * © 2024 OWLBAN GROUP 🦉 - All Rights Reserved
 * Owned by: King Sachem Yochanan (Oscar Broome)
 * Authority: House of David ✡️, House of Capet ⚜️, House of Logan 🏰
 * 
 * KING'S BANKING ABILITY - Royal Treasury & Sovereign Wealth Management
 * PROTECTED BY CUSTOM ENCRYPTION - DO NOT SHARE
 */

import express from 'express';
import PrivateBankingService from '../services/privateBankingService.js';

const router = express.Router();
const bankingService = new PrivateBankingService();

// Initialize banking accounts and assets
bankingService.initializeAccounts();
bankingService.initializeAssets();

// ============================================
// KING'S TREASURY ENDPOINTS
// ============================================

// GET /api/private-banking/health - Health check
router.get('/health', (_req, res) => {
  res.json(bankingService.getHealthStatus());
});

// GET /api/private-banking/treasury - Get Royal Treasury Summary
router.get('/treasury', (_req, res) => {
  const summary = bankingService.getPortfolioSummary();
  
  // Add King's specific metadata
  res.json({
    ...summary,
    sovereign: {
      title: 'King Sachem Yochanan',
      authority: 'House of David ✡️, House of Capet ⚜️, House of Logan 🏰',
      status: '👑 ACTIVE - FULL SOVEREIGN CONTROL',
      liquidityProtection: bankingService.protectionLimits !== null,
      creditCrisisMode: bankingService.creditCrisisMode,
    },
    timestamp: new Date().toISOString(),
  });
});

// GET /api/private-banking/treasury/full - Get Full Treasury Details
router.get('/treasury/full', (_req, res) => {
  const exportData = bankingService.exportBankingData();
  
  res.json({
    ...exportData,
    sovereign: {
      title: 'King Sachem Yochanan',
      authority: 'House of David ✡️, House of Capet ⚜️, House of Logan 🏰',
      status: '👑 ACTIVE',
    },
    timestamp: new Date().toISOString(),
  });
});

// GET /api/private-banking/sovereign-status - Get Sovereign Override Status
router.get('/sovereign-status', (_req, res) => {
  res.json({
    sovereignOverrideActive: bankingService.sovereignOverrideActive,
    creditCrisisMode: bankingService.creditCrisisMode,
    protectionLimits: bankingService.protectionLimits,
    status: bankingService.sovereignOverrideActive 
      ? '👑 SOVEREIGN OVERRIDE ACTIVE - FULL CONTROL' 
      : '🛡️ STANDARD OPERATION',
    timestamp: new Date().toISOString(),
  });
});

// POST /api/private-banking/activate-sovereign - Activate Sovereign Override
router.post('/activate-sovereign', (_req, res) => {
  const result = bankingService.activateSovereignOverride();
  
  res.json({
    success: true,
    message: '👑 SOVEREIGN OVERRIDE ACTIVATED - King Sachem Yochanan has FULL CONTROL',
    result,
    timestamp: new Date().toISOString(),
  });
});

// POST /api/private-banking/activate-protections - Activate Liquidity Protection
router.post('/activate-protections', (_req, res) => {
  const result = bankingService.activateLiquidityProtection();
  
  res.json({
    success: true,
    message: '🛡️ LIQUIDITY PROTECTION ACTIVATED - All earned balances protected',
    result,
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// KING'S ACCOUNTS ENDPOINTS
// ============================================

// GET /api/private-banking/accounts - Get All King/Accounts
router.get('/accounts', (_req, res) => {
  const accounts = /** @type {Array<any>} */ (bankingService.getAccounts());
  
  res.json({
    accounts,
    count: accounts.length,
    totalBalance: accounts.reduce((sum, acc) => {
      // Extract numeric value from formatted string
      const value = parseFloat(acc.balance.replace(/[^0-9.-]+/g, ''));
      return sum + (isNaN(value) ? 0 : value);
    }, 0),
    timestamp: new Date().toISOString(),
  });
});

// GET /api/private-banking/accounts/:accountId - Get Specific Account
router.get('/accounts/:accountId', (req, res) => {
  const { accountId } = req.params;
  const account = bankingService.getAccount(accountId);
  
  if (!account) {
    return res.status(404).json({ 
      error: 'Account not found',
      message: 'No account found with ID: ' + accountId 
    });
  }
  
  res.json({
    account,
    timestamp: new Date().toISOString(),
  });
});

// POST /api/private-banking/accounts/:accountId/balance - Update Account Balance
router.post('/accounts/:accountId/balance', (req, res) => {
  const { accountId } = req.params;
  const { newBalance, transactionType, description } = req.body;
  
  if (newBalance === undefined || newBalance === null) {
    return res.status(400).json({ error: 'newBalance is required' });
  }
  
  const result = /** @type {{success: boolean, error?: string}} */ (bankingService.updateAccountBalance(
    accountId,
    newBalance,
    transactionType || 'adjustment',
    description || 'Balance adjustment via King\'s Treasury'
  ));
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.json({
    ...result,
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// KING'S ASSETS ENDPOINTS
// ============================================

// GET /api/private-banking/assets - Get All Kingdom Assets
router.get('/assets', (_req, res) => {
  const assets = bankingService.getAssets();
  
  res.json({
    assets,
    count: assets.length,
    timestamp: new Date().toISOString(),
  });
});

// GET /api/private-banking/assets/:assetId - Get Specific Asset
router.get('/assets/:assetId', (req, res) => {
  const { assetId } = req.params;
  const asset = bankingService.getAsset(assetId);
  
  if (!asset) {
    return res.status(404).json({ 
      error: 'Asset not found',
      message: 'No asset found with ID: ' + assetId 
    });
  }
  
  res.json({
    asset,
    timestamp: new Date().toISOString(),
  });
});

// POST /api/private-banking/assets/:assetId/value - Update Asset Value
router.post('/assets/:assetId/value', (req, res) => {
  const { assetId } = req.params;
  const { newValue, reason } = req.body;
  
  if (newValue === undefined || newValue === null) {
    return res.status(400).json({ error: 'newValue is required' });
  }
  
  const result = /** @type {{success: boolean, error?: string}} */ (bankingService.updateAssetValue(
    assetId,
    newValue,
    reason || 'valuation'
  ));
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.json({
    ...result,
    timestamp: new Date().toISOString(),
  });
});

// GET /api/private-banking/assets/:assetId/history - Get Asset History
router.get('/assets/:assetId/history', (req, res) => {
  const { assetId } = req.params;
  const days = req.query.days ? parseInt(String(req.query.days)) : 30;
  
  const history = bankingService.getAssetHistory(assetId, days);
  
  res.json({
    assetId,
    history,
    days,
    count: history.length,
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// KING'S TRANSACTIONS ENDPOINTS
// ============================================

// GET /api/private-banking/transactions - Get Transaction History
router.get('/transactions', (req, res) => {
  const accountId = req.query.accountId ? String(req.query.accountId) : undefined;
  const limit = req.query.limit ? parseInt(String(req.query.limit)) : 100;
  
  const transactions = bankingService.getTransactionHistory(accountId, limit);
  
  res.json({
    transactions,
    count: transactions.length,
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// KING'S BANKING OPERATIONS ENDPOINTS
// ============================================

// POST /api/private-banking/operations/transfer - Execute Transfer
router.post('/operations/transfer', (req, res) => {
  const { fromAccountId, toAccountId, amount, description } = req.body;
  
  if (!fromAccountId || !toAccountId || !amount) {
    return res.status(400).json({ 
      error: 'fromAccountId, toAccountId, and amount are required' 
    });
  }
  
  const result = /** @type {{success: boolean, error?: string, message?: string}} */ (bankingService.executeTransfer(fromAccountId, {
    toAccountId,
    amount,
    description: description || 'Royal Transfer',
  }));
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.json({
    ...result,
    timestamp: new Date().toISOString(),
  });
});

// POST /api/private-banking/operations/deposit - Execute Deposit
router.post('/operations/deposit', (req, res) => {
  const { accountId, amount, description } = req.body;
  
  if (!accountId || !amount) {
    return res.status(400).json({ 
      error: 'accountId and amount are required' 
    });
  }
  
  const result = /** @type {{success: boolean, error?: string, message?: string}} */ (bankingService.executeDeposit(accountId, {
    amount,
    description: description || 'Royal Deposit',
  }));
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.json({
    ...result,
    timestamp: new Date().toISOString(),
  });
});

// POST /api/private-banking/operations/withdrawal - Execute Withdrawal
router.post('/operations/withdrawal', (req, res) => {
  const { accountId, amount, description } = req.body;
  
  if (!accountId || !amount) {
    return res.status(400).json({ 
      error: 'accountId and amount are required' 
    });
  }
  
  const result = /** @type {{success: boolean, error?: string, message?: string}} */ (bankingService.executeWithdrawal(accountId, {
    amount,
    description: description || 'Royal Withdrawal',
  }));
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.json({
    ...result,
    timestamp: new Date().toISOString(),
  });
});

// POST /api/private-banking/operations/pay-bill - Pay Bill from King/Accounts
router.post('/operations/pay-bill', (req, res) => {
  const { billAmount, billDescription, fromAccountId } = req.body;
  
  if (!billAmount || !billDescription) {
    return res.status(400).json({ 
      error: 'billAmount and billDescription are required' 
    });
  }
  
  const result = /** @type {{success: boolean, error?: string, message?: string}} */ (bankingService.payBill(
    billAmount,
    billDescription,
    fromAccountId || 'primary-checking'
  ));
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.json({
    ...result,
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// KING'S WEALTH ENDPOINTS
// ============================================

// GET /api/private-banking/wealth - Get Total Kingdom Wealth
router.get('/wealth', (_req, res) => {
  const summary = bankingService.getPortfolioSummary();
  
  // Parse total values from formatted strings
  const totalPortfolio = parseFloat(
    summary.totalPortfolioValue.replace(/[^0-9.-]+/g, '')
  );
  const totalAccounts = parseFloat(
    summary.totalAccountBalance.replace(/[^0-9.-]+/g, '')
  );
  const totalAssets = parseFloat(
    summary.totalAssetValue.replace(/[^0-9.-]+/g, '')
  );
  
  res.json({
    wealth: {
      totalPortfolioValue: totalPortfolio,
      totalAccountBalance: totalAccounts,
      totalAssetValue: totalAssets,
      performance: summary.performance,
      assetAllocation: summary.assetAllocation,
    },
    sovereign: {
      title: 'King Sachem Yochanan',
      authority: 'House of David ✡️, House of Capet ⚜️, House of Logan 🏰',
      status: '👑 ACTIVE',
    },
    timestamp: new Date().toISOString(),
  });
});

// GET /api/private-banking/wealth/owner - Get Owner Balance (King's Access)
router.get('/wealth/owner', (req, res) => {
  const accountId = req.query.accountId ? String(req.query.accountId) : undefined;
  
  const balance = bankingService.getOwnerBalance(accountId);
  
  res.json({
    ownerBalance: balance,
    formattedBalance: bankingService.formatCurrency(balance, 'USD'),
    accountId: accountId || 'all-accounts',
    sovereign: {
      title: 'King Sachem Yochanan',
      access: 'FULL OWNER ACCESS',
    },
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// EXPORT ENDPOINT
// ============================================

// GET /api/private-banking/export - Export All Banking Data
router.get('/export', (_req, res) => {
  const exportData = bankingService.exportBankingData();
  
  res.json({
    ...exportData,
    sovereign: {
      title: 'King Sachem Yochanan',
      authority: 'House of David ✡️, House of Capet ⚜️, House of Logan 🏰',
      status: '👑 EXPORT COMPLETE',
    },
    timestamp: new Date().toISOString(),
  });
});

export default router;
