function toNumber(value) {
  if (value === undefined || value === null || value === '') return undefined;
  const num = Number(value);
  return Number.isFinite(num) ? num : undefined;
}

function normalizeDate(value) {
  if (!value || typeof value !== 'string') return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

const MOCK_TRANSACTIONS = [
  {
    id: 'txn_1001',
    accountId: 'acct_operating_001',
    type: 'credit',
    amount: 25000,
    currency: 'USD',
    description: 'Initial funding',
    postedAt: '2026-06-01T10:30:00.000Z'
  },
  {
    id: 'txn_1002',
    accountId: 'acct_operating_001',
    type: 'debit',
    amount: 420.5,
    currency: 'USD',
    description: 'Office supplies',
    postedAt: '2026-06-03T15:12:00.000Z'
  },
  {
    id: 'txn_1003',
    accountId: 'acct_payroll_002',
    type: 'debit',
    amount: 4800,
    currency: 'USD',
    description: 'Payroll batch',
    postedAt: '2026-06-05T13:00:00.000Z'
  },
  {
    id: 'txn_1004',
    accountId: 'acct_operating_001',
    type: 'credit',
    amount: 1200,
    currency: 'USD',
    description: 'Client payment',
    postedAt: '2026-06-07T09:05:00.000Z'
  }
];

export function listTransactions(filters = {}) {
  const {
    accountId,
    type,
    minAmount,
    maxAmount,
    startDate,
    endDate,
    limit
  } = filters;

  const parsedMin = toNumber(minAmount);
  const parsedMax = toNumber(maxAmount);
  const parsedStart = normalizeDate(startDate);
  const parsedEnd = normalizeDate(endDate);
  const parsedLimit = toNumber(limit);

  if (parsedMin !== undefined && parsedMax !== undefined && parsedMin > parsedMax) {
    const err = new Error('Validation failed');
    err.statusCode = 400;
    err.publicMessage = 'Invalid transaction filters';
    err.validationErrors = ['minAmount cannot be greater than maxAmount.'];
    throw err;
  }

  let data = [...MOCK_TRANSACTIONS];

  if (accountId) {
    data = data.filter((txn) => txn.accountId === accountId);
  }

  if (type) {
    data = data.filter((txn) => txn.type === type);
  }

  if (parsedMin !== undefined) {
    data = data.filter((txn) => txn.amount >= parsedMin);
  }

  if (parsedMax !== undefined) {
    data = data.filter((txn) => txn.amount <= parsedMax);
  }

  if (parsedStart) {
    data = data.filter((txn) => new Date(txn.postedAt) >= parsedStart);
  }

  if (parsedEnd) {
    data = data.filter((txn) => new Date(txn.postedAt) <= parsedEnd);
  }

  if (parsedLimit !== undefined && parsedLimit > 0) {
    data = data.slice(0, parsedLimit);
  }

  return {
    count: data.length,
    transactions: data
  };
}
