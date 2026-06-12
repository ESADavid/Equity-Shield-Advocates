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

function validateTrusteeSigner(signer) {
  return (
    signer &&
    isNonEmptyString(signer.name) &&
    isNonEmptyString(signer.role) &&
    isNonEmptyString(signer.email)
  );
}

function validateTrustAccount(account) {
  const validTypes = new Set(['primary', 'reserve']);
  return (
    account &&
    isNonEmptyString(account.name) &&
    isNonEmptyString(account.type) &&
    validTypes.has(account.type.toLowerCase())
  );
}

function toCurrency(value) {
  return typeof value === 'number' && Number.isFinite(value)
    ? value.toFixed(2)
    : '0.00';
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

export function buildFamilyTrustIntegrationPlan(payload) {
  const errors = [];

  if (!payload || typeof payload !== 'object') {
    errors.push('Payload must be a JSON object.');
  }

  if (!isNonEmptyString(payload?.trustName)) {
    errors.push('trustName is required and must be a non-empty string.');
  }

  if (!Array.isArray(payload?.trusteeSigners) || payload.trusteeSigners.length === 0) {
    errors.push('trusteeSigners must be a non-empty array.');
  } else {
    payload.trusteeSigners.forEach((s, idx) => {
      if (!validateTrusteeSigner(s)) {
        errors.push(`trusteeSigners[${idx}] is invalid. Required: name, role, email.`);
      }
    });
  }

  if (!Array.isArray(payload?.trustAccounts) || payload.trustAccounts.length < 2) {
    errors.push('trustAccounts must include at least primary and reserve accounts.');
  } else {
    payload.trustAccounts.forEach((a, idx) => {
      if (!validateTrustAccount(a)) {
        errors.push(`trustAccounts[${idx}] is invalid. Required: name, type(primary|reserve).`);
      }
    });

    const accountTypes = new Set(payload.trustAccounts.map((a) => a.type.toLowerCase()));
    if (!accountTypes.has('primary') || !accountTypes.has('reserve')) {
      errors.push('trustAccounts must include both a primary and reserve account type.');
    }
  }

  if (!payload?.transferPolicy || typeof payload.transferPolicy !== 'object') {
    errors.push('transferPolicy is required and must be an object.');
  } else {
    if (!isNonEmptyString(payload.transferPolicy.purposeMemoTemplate)) {
      errors.push('transferPolicy.purposeMemoTemplate is required.');
    }
    if (typeof payload.transferPolicy.dualApprovalThreshold !== 'number' || payload.transferPolicy.dualApprovalThreshold < 0) {
      errors.push('transferPolicy.dualApprovalThreshold must be a number >= 0.');
    }
    if (payload.transferPolicy.requiresTrusteeApproval !== true) {
      errors.push('transferPolicy.requiresTrusteeApproval must be true.');
    }
  }

  if (!payload?.separationControls || typeof payload.separationControls !== 'object') {
    errors.push('separationControls is required and must be an object.');
  } else {
    if (payload.separationControls.noCommingling !== true) {
      errors.push('separationControls.noCommingling must be true.');
    }
    if (payload.separationControls.entityAccountsIndependent !== true) {
      errors.push('separationControls.entityAccountsIndependent must be true.');
    }
  }

  if (errors.length > 0) {
    const err = new Error('Validation failed');
    err.statusCode = 400;
    err.publicMessage = 'Invalid family trust integration payload';
    err.validationErrors = errors;
    throw err;
  }

  const threshold = payload.transferPolicy.dualApprovalThreshold;
  const trusteeEmails = payload.trusteeSigners.map((s) => s.email);

  return {
    trustName: payload.trustName,
    governance: {
      legalSeparationRequired: true,
      conflictRule: 'If corporate instruction conflicts with trust terms, trustee follows trust terms first.'
    },
    accountTopology: {
      trustPrimary: payload.trustAccounts.find((a) => a.type.toLowerCase() === 'primary')?.name || null,
      trustReserve: payload.trustAccounts.find((a) => a.type.toLowerCase() === 'reserve')?.name || null,
      entityAccountsRemainSeparate: true
    },
    transferControls: {
      noCommingling: true,
      purposeMemoRequired: true,
      trusteeApprovalRequired: true,
      dualApproval: {
        thresholdAmount: threshold,
        thresholdDisplay: `$${toCurrency(threshold)}`
      }
    },
    requiredRecordsPacket: [
      'Family Trust instrument + amendments',
      'Trustee acceptance/succession records',
      'Trust-specific banking authorizations',
      'Trust <-> entity transfer memos',
      'Distribution justifications',
      'Reconciliations and year-end accounting files'
    ],
    nextActions: [
      'Confirm trustee KYC packet and signer matrix',
      'Verify trust primary/reserve account configuration',
      'Enable dual approval and alert controls',
      'Adopt transfer memo template and retention workflow'
    ],
    trusteeSignerCount: payload.trusteeSigners.length,
    trusteeSignerEmails: trusteeEmails
  };
}
