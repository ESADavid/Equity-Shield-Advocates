/**
 * Banking Setup Service
 * Handles entity banking setup workflow with validation
 */

/**
 * Validate banking setup payload
 */
export function validateBankingSetupPayload(payload) {
  const errors = [];
  
  if (!payload.entityName || typeof payload.entityName !== 'string') {
    errors.push('entityName is required and must be a string');
  }
  
  if (!payload.ein || typeof payload.ein !== 'string') {
    errors.push('ein is required and must be a string');
  }
  
  // Validate EIN format (XX-XXXXXXX)
  if (payload.ein && !/^\d{2}-?\d{7}$/.test(payload.ein.replace(/^(\d{2})(\d{7})$/, '$1-$2'))) {
    errors.push('ein must be a valid EIN format (XX-XXXXXXX)');
  }
  
  if (!payload.authorizedSigners || !Array.isArray(payload.authorizedSigners)) {
    errors.push('authorizedSigners is required and must be an array');
  } else if (payload.authorizedSigners.length === 0) {
    errors.push('at least one authorized signer is required');
  } else {
    payload.authorizedSigners.forEach((signer, index) => {
      if (!signer.name || typeof signer.name !== 'string') {
        errors.push(`signer[${index}].name is required`);
      }
      if (!signer.title || typeof signer.title !== 'string') {
        errors.push(`signer[${index}].title is required`);
      }
    });
  }
  
  if (!payload.accounts || !Array.isArray(payload.accounts)) {
    errors.push('accounts is required and must be an array');
  } else if (payload.accounts.length === 0) {
    errors.push('at least one account is required');
  } else {
    payload.accounts.forEach((account, index) => {
      if (!account.type || typeof account.type !== 'string') {
        errors.push(`accounts[${index}].type is required`);
      }
      if (!account.purpose || typeof account.purpose !== 'string') {
        errors.push(`accounts[${index}].purpose is required`);
      }
    });
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Generate banking setup plan
 */
export function generateBankingSetupPlan(payload) {
  return {
    entityName: payload.entityName,
    ein: payload.ein,
    status: 'pending',
    nextActions: [
      '1. Submit entity documentation to bank',
      '2. Complete beneficial ownership verification',
      '3. Schedule banker onboarding call',
      '4. Fund accounts per account type',
      '5. Configure online banking and access controls',
      '6. Enable ACH/wire permissions',
      '7. Set up dual-approval thresholds',
      '8. Configure fraud alerts and notifications'
    ],
    accounts: payload.accounts.map(account => ({
      ...account,
      status: 'pending',
      estimatedActivationDays: account.type === 'checking' ? 3 : 5
    })),
    signers: payload.authorizedSigners.map(signer => ({
      ...signer,
      status: 'pending'
    })),
    createdAt: new Date().toISOString()
  };
}
