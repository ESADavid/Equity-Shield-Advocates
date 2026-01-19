import React from 'react';

function ErrorRecovery({
  error,
  onRetry,
  onUpdateMode,
  onDismiss,
  showUpdateOption = false
}) {
  const getErrorMessage = (error) => {
    if (!error) return 'An unknown error occurred';

    // Map Plaid error codes to user-friendly messages
    const errorMappings = {
      'INVALID_ACCESS_TOKEN': 'Your bank connection has expired. Please reconnect your account.',
      'ITEM_LOGIN_REQUIRED': 'Your bank requires re-authentication. Please update your connection.',
      'PENDING_DISCONNECT': 'Your bank connection is pending disconnection. Please update your credentials.',
      'PENDING_EXPIRATION': 'Your bank connection is about to expire. Please update your credentials.',
      'USER_PERMISSION_REVOKED': 'Your bank has revoked access. Please reconnect your account.',
      'ACCOUNT_LOCKED': 'Your bank account is temporarily locked. Please contact your bank.',
      'RATE_LIMIT_EXCEEDED': 'Too many requests. Please try again in a moment.',
      'PRODUCT_NOT_READY': 'Bank data is still being processed. Please try again later.',
    };

    const plaidErrorCode = error.error_code || error.code;
    return errorMappings[plaidErrorCode] || error.message || error.error_message || 'An error occurred while processing your request.';
  };

  const getRecoveryActions = (error) => {
    if (!error) return [];

    const plaidErrorCode = error.error_code || error.code;
    const actions = [];

    switch (plaidErrorCode) {
      case 'ITEM_LOGIN_REQUIRED':
      case 'PENDING_DISCONNECT':
      case 'PENDING_EXPIRATION':
        actions.push({
          label: 'Update Connection',
          action: onUpdateMode,
          primary: true
        });
        break;
      case 'USER_PERMISSION_REVOKED':
        actions.push({
          label: 'Reconnect Account',
          action: onUpdateMode,
          primary: true
        });
        break;
      default:
        actions.push({
          label: 'Retry',
          action: onRetry,
          primary: true
        });
    }

    actions.push({
      label: 'Dismiss',
      action: onDismiss,
      primary: false
    });

    return actions;
  };

  const errorMessage = getErrorMessage(error);
  const actions = getRecoveryActions(error);

  return (
    <div className="error-recovery-modal">
      <div className="error-recovery-content">
        <div className="error-icon">
          <span>⚠️</span>
        </div>
        <h3>Connection Issue</h3>
        <p className="error-message">{errorMessage}</p>

        <div className="error-details">
          {error && (error.error_code || error.code) && (
            <small>
              Error Code: {error.error_code || error.code}
            </small>
          )}
        </div>

        <div className="error-actions">
          {actions.map((action, index) => (
            <button
              key={index}
              onClick={action.action}
              className={`btn ${action.primary ? 'btn-primary' : 'btn-secondary'}`}
            >
              {action.label}
            </button>
          ))}
        </div>

        {showUpdateOption && (
          <div className="update-mode-info">
            <p>
              <strong>Update Mode:</strong> This will allow you to fix your bank connection
              without losing your existing account data.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default ErrorRecovery;
