import React, { useState, useEffect } from 'react';
import PlaidLink from './PlaidLink.jsx';

function ErrorRecovery({
  userId,
  onSuccess,
  onError,
  onUpdateModeTriggered,
  itemId,
  errorCode,
  errorMessage,
  autoTriggerUpdate = true
}) {
  const [showUpdateMode, setShowUpdateMode] = useState(false);
  const [recoveryAttempts, setRecoveryAttempts] = useState(0);
  const [lastError, setLastError] = useState(null);

  // Error recovery logic
  useEffect(() => {
    if (errorCode && autoTriggerUpdate) {
      handleErrorRecovery(errorCode, errorMessage);
    }
  }, [errorCode, errorMessage, autoTriggerUpdate]);

  const handleErrorRecovery = (code, message) => {
    setLastError({ code, message });

    switch (code) {
      case 'ITEM_LOGIN_REQUIRED':
        // Automatically trigger update mode for login required errors
        console.warn('ITEM_LOGIN_REQUIRED detected - triggering update mode');
        setShowUpdateMode(true);
        if (onUpdateModeTriggered) {
          onUpdateModeTriggered('ITEM_LOGIN_REQUIRED');
        }
        break;

      case 'PENDING_DISCONNECT':
        // Show reconnection prompt
        setShowUpdateMode(true);
        if (onUpdateModeTriggered) {
          onUpdateModeTriggered('PENDING_DISCONNECT');
        }
        break;

      case 'PENDING_EXPIRATION':
        // Alert user to refresh connection
        setShowUpdateMode(true);
        if (onUpdateModeTriggered) {
          onUpdateModeTriggered('PENDING_EXPIRATION');
        }
        break;

      case 'USER_PERMISSION_REVOKED':
        // Guide to re-link account
        setShowUpdateMode(true);
        if (onUpdateModeTriggered) {
          onUpdateModeTriggered('USER_PERMISSION_REVOKED');
        }
        break;

      default:
        // For other errors, show retry option
        setRecoveryAttempts(prev => prev + 1);
        break;
    }
  };

  const handleUpdateSuccess = (data, metadata) => {
    logger.info('Update mode successful - connection restored');
    setShowUpdateMode(false);
    setRecoveryAttempts(0);
    setLastError(null);
    onSuccess && onSuccess(data, metadata);
  };

  const handleUpdateExit = (err, metadata) => {
    if (err) {
      logger.error('Update mode failed:', err);
      setRecoveryAttempts(prev => prev + 1);
    }
    onError && onError(err, metadata);
  };

  const getErrorMessage = (code, message) => {
    const errorMessages = {
      'ITEM_LOGIN_REQUIRED': 'Your bank requires re-authentication. Please update your connection.',
      'PENDING_DISCONNECT': 'Your bank connection is pending disconnection. Please reconnect.',
      'PENDING_EXPIRATION': 'Your bank connection is expiring soon. Please refresh it.',
      'USER_PERMISSION_REVOKED': 'Your bank permissions have been revoked. Please reconnect.',
      'RATE_LIMIT_EXCEEDED': 'Too many requests. Please try again in a moment.',
      'PRODUCT_NOT_READY': 'Bank data is still being processed. Please try again later.',
    };

    return errorMessages[code] || (message ? message.replace(/[<>'"&]/g, '') : 'An error occurred. Please try again.');
  };

  const getRecoveryAction = (code) => {
    const actions = {
      'ITEM_LOGIN_REQUIRED': 'Update Connection',
      'PENDING_DISCONNECT': 'Reconnect Account',
      'PENDING_EXPIRATION': 'Refresh Connection',
      'USER_PERMISSION_REVOKED': 'Reconnect Account',
    };

    return actions[code] || 'Retry';
  };

  if (showUpdateMode) {
    return (
      <div className="error-recovery-container">
        <div className="error-recovery-header">
          <h3>🔄 Connection Update Required</h3>
          <p>{getErrorMessage(lastError?.code, lastError?.message)}</p>
        </div>

        <div className="error-recovery-actions">
          <PlaidLink
            userId={userId}
            mode="update"
            itemId={itemId}
            onSuccess={handleUpdateSuccess}
            onExit={handleUpdateExit}
            updateModeTrigger={lastError?.code}
            buttonStyle={{
              backgroundColor: '#ff6b35',
              border: 'none',
              padding: '12px 24px',
              borderRadius: '6px',
              color: 'white',
              fontWeight: 'bold',
              cursor: 'pointer'
            }}
          >
            {getRecoveryAction(lastError?.code)}
          </PlaidLink>

          <button
            onClick={() => setShowUpdateMode(false)}
            className="btn btn-secondary"
            style={{ marginLeft: '10px' }}
          >
            Cancel
          </button>
        </div>

        <div className="error-recovery-info">
          <small>
            This will securely reconnect your account without requiring you to re-enter your bank credentials.
          </small>
        </div>
      </div>
    );
  }

  if (lastError && !showUpdateMode) {
    return (
      <div className="error-display">
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          <span>{getErrorMessage(lastError.code, lastError.message)}</span>
        </div>

        <div className="error-actions">
          {recoveryAttempts < 3 && (
            <button
              onClick={() => handleErrorRecovery(lastError.code, lastError.message)}
              className="btn btn-primary"
            >
              {getRecoveryAction(lastError.code)}
            </button>
          )}

          {recoveryAttempts >= 3 && (
            <div className="error-help">
              <p>Multiple recovery attempts failed. Please contact support.</p>
              <button
                onClick={() => window.location.reload()}
                className="btn btn-secondary"
              >
                Refresh Page
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  return null;
}

export default ErrorRecovery;
