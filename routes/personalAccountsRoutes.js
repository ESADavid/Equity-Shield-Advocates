/**
 * Personal Accounts Routes
 * OSCAR-BROOME-REVENUE System - Proprietary Technology
 * 
 * © 2024 OWLBAN GROUP 🦉 - All Rights Reserved
 * Owned by: King Sachem Yochanan (Oscar Broome)
 * Authority: House of David ✡️, House of Capet ⚜️, House of Logan 🏰
 * 
 * PROTECTED BY CUSTOM ENCRYPTION - DO NOT SHARE
 */

import express from 'express';
import { authenticateToken } from '../utils/authMiddleware.js';
import PersonalAccountsService from '../services/personalAccountsService.js';

const router = express.Router();
const accountsService = new PersonalAccountsService();

router.use(authenticateToken);

// GET /api/accounts/health - Health check
router.get('/health', (_req, res) => {
  res.json(accountsService.getHealthStatus());
});

// GET /api/accounts/summary - Get banking summary
router.get('/summary', (_req, res) => {
  res.json(accountsService.getBankingSummary());
});

// GET /api/accounts/bank - Get all bank accounts
router.get('/bank', (_req, res) => {
  res.json(accountsService.getBankAccounts());
});

// GET /api/accounts/bank/:accountId - Get specific bank account
router.get('/bank/:accountId', (req, res) => {
  const { accountId } = req.params;
  const account = accountsService.getBankAccount(accountId);
  
  if (!account) {
    return res.status(404).json({ error: 'Account not found' });
  }
  
  res.json(account);
});

// GET /api/accounts/bank/:accountId/balance - Get account balance
router.get('/bank/:accountId/balance', async (req, res) => {
  const { accountId } = req.params;
  const result = await accountsService.getAccountBalance(accountId);
  
  if (!result.success) {
    return res.status(404).json({ error: result.error });
  }
  
  res.json(result);
});

// POST /api/accounts/bank/link - Link bank account via Plaid
router.post('/bank/link', async (req, res) => {
  const { publicToken, institutionId, accountData } = req.body;
  
  if (!publicToken || !institutionId) {
    return res.status(400).json({ error: 'publicToken and institutionId are required' });
  }
  
  const result = await accountsService.linkBankAccount(
    publicToken,
    institutionId,
    accountData || {}
  );
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.status(201).json(result);
});

// DELETE /api/accounts/bank/:accountId - Unlink bank account
router.delete('/bank/:accountId', async (req, res) => {
  const { accountId } = req.params;
  const result = await accountsService.unlinkBankAccount(accountId);
  
  if (!result.success) {
    return res.status(404).json({ error: result.error });
  }
  
  res.json(result);
});

// GET /api/accounts/cards - Get all cards
router.get('/cards', (_req, res) => {
  res.json(accountsService.getCards());
});

// GET /api/accounts/cards/:cardId - Get specific card
router.get('/cards/:cardId', (req, res) => {
  const { cardId } = req.params;
  const card = accountsService.getCard(cardId);
  
  if (!card) {
    return res.status(404).json({ error: 'Card not found' });
  }
  
  res.json(card);
});

// POST /api/accounts/cards - Create virtual card
router.post('/cards', (req, res) => {
  const { network, name, limit, cardholderName } = req.body;
  
  const result = accountsService.createVirtualCard({
    network,
    name,
    limit,
    cardholderName,
  });
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.status(201).json(result);
});

// POST /api/accounts/cards/:cardId/block - Block card
router.post('/cards/:cardId/block', (req, res) => {
  const { cardId } = req.params;
  const result = accountsService.blockCard(cardId);
  
  if (!result.success) {
    return res.status(404).json({ error: result.error });
  }
  
  res.json(result);
});

// POST /api/accounts/cards/:cardId/unblock - Unblock card
router.post('/cards/:cardId/unblock', (req, res) => {
  const { cardId } = req.params;
  const result = accountsService.unblockCard(cardId);
  
  if (!result.success) {
    return res.status(404).json({ error: result.error });
  }
  
  res.json(result);
});

// POST /api/accounts/cards/:cardId/transaction - Process card transaction
router.post('/cards/:cardId/transaction', (req, res) => {
  const { cardId } = req.params;
  const { amount, description } = req.body;
  
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Valid positive amount is required' });
  }
  
  const result = accountsService.processCardTransaction(
    cardId,
    amount,
    description || 'Card transaction'
  );
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.json(result);
});

// POST /api/accounts/transfer - Transfer between accounts
router.post('/transfer', async (req, res) => {
  const { fromAccountId, toAccountId, amount, description } = req.body;
  
  if (!fromAccountId || !toAccountId || !amount) {
    return res.status(400).json({ 
      error: 'fromAccountId, toAccountId, and amount are required' 
    });
  }
  
  const result = await accountsService.transferFunds(
    fromAccountId,
    toAccountId,
    amount,
    description || 'Transfer'
  );
  
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  
  res.json(result);
});

// GET /api/accounts/transactions - Get transaction history
router.get('/transactions', (req, res) => {
  const accountId = req.query.accountId ? String(req.query.accountId) : undefined;
  const cardId = req.query.cardId ? String(req.query.cardId) : undefined;
  const limit = req.query.limit ? parseInt(String(req.query.limit)) : 50;
  
  const result = accountsService.getTransactionHistory({
    accountId,
    cardId,
    limit,
  });
  
  res.json(result);
});

// GET /api/accounts/export - Export all account data
router.get('/export', (_req, res) => {
  res.json(accountsService.exportAccountData());
});

export default router;
