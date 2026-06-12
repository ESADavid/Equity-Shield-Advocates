function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function validateSigner(signer) {
  return (
    signer &&
    isNonEmptyString(signer.name) &&
    isNonEmptyString(signer.title) &&
    isNonEmptyString(signer.email)
  );
}

function validateAccount(account) {
  return (
    account &&
    isNonEmptyString(account.type) &&
    typeof account.initialDeposit === 'number' &&
    account.initialDeposit >= 0
  );
}

export function buildBankingSetupPlan(payload) {
  const errors = [];

  if (!payload || typeof payload !== 'object') {
    errors.push('Payload must be a JSON object.');
  }

  if (!isNonEmptyString(payload?.entityName)) {
    errors.push('entityName is required and must be a non-empty string.');
  }

  if (!isNonEmptyString(payload?.ein)) {
    errors.push('ein is required and must be a non-empty string.');
  }

  if (!Array.isArray(payload?.authorizedSigners) || payload.authorizedSigners.length === 0) {
    errors.push('authorizedSigners must be a non-empty array.');
  } else {
    payload.authorizedSigners.forEach((s, idx) => {
      if (!validateSigner(s)) {
        errors.push(`authorizedSigners[${idx}] is invalid. Required: name, title, email.`);
      }
    });
  }

  if (!Array.isArray(payload?.accounts) || payload.accounts.length === 0) {
    errors.push('accounts must be a non-empty array.');
  } else {
    payload.accounts.forEach((a, idx) => {
      if (!validateAccount(a)) {
        errors.push(`accounts[${idx}] is invalid. Required: type, initialDeposit(number >= 0).`);
      }
    });
  }

  if (errors.length > 0) {
    const err = new Error('Validation failed');
    err.statusCode = 400;
    err.publicMessage = 'Invalid banking setup payload';
    err.validationErrors = errors;
    throw err;
  }

  return {
    entityName: payload.entityName,
    einLast4: payload.ein.slice(-4),
    setupPlan: [
      'KYC/KYB document collection',
      'Authorized signer verification',
      'Account product configuration',
      'Funding and activation'
    ],
    nextActions: [
      'Upload incorporation docs',
      'Provide signer IDs',
      'Confirm initial funding schedule'
    ],
    accountCount: payload.accounts.length,
    signerCount: payload.authorizedSigners.length
  };
}
