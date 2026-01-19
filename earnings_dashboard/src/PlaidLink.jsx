import React, { useState, useEffect } from 'react';
import { usePlaidLink } from 'react-plaid-link';

function PlaidLink({
  onSuccess,
  onExit,
  userId,
  products = ['transactions', 'balances', 'income'],
  linkToken: providedLinkToken,
  mode = 'link', // 'link' or 'update'
  institutionId,
  accountFilters,
  paymentInitiation,
  redirectUri,
  oauth = false, // Enable OAuth support
  longtail = true,
  forceIframe = false
}) {
  const [linkToken, setLinkToken] = useState(providedLinkToken || null);
  const [loading, setLoading] = useState(!providedLinkToken);
  const [error, setError] = useState(null);

  // Fetch link token from backend if not provided
  useEffect(() => {
    if (providedLinkToken || !userId) return;

    const fetchLinkToken = async () => {
      try {
        const requestBody = {
          userId: userId || 'user_default',
          products: products,
          mode: mode,
        };

        // Add optional parameters
        if (institutionId) requestBody.institutionId = institutionId;
        if (accountFilters) requestBody.accountFilters = accountFilters;
        if (paymentInitiation) requestBody.paymentInitiation = paymentInitiation;
        if (redirectUri) requestBody.redirectUri = redirectUri;
        if (oauth !== undefined) requestBody.oauth = oauth;

        const response = await fetch('/api/plaid/create-link-token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestBody),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.message || 'Failed to create link token');
        }

        setLinkToken(data.data.link_token);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchLinkToken();
  }, [userId, products, mode, institutionId, accountFilters, paymentInitiation, redirectUri, providedLinkToken]);

  // Handle successful Plaid Link connection
  const handleOnSuccess = async (publicToken, metadata) => {
    try {
      // Exchange public token for access token
      const response = await fetch('/api/plaid/exchange-public-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ publicToken }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Failed to exchange token');
      }

      // Call parent success handler
      if (onSuccess) {
        onSuccess(data.data, metadata);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  // Handle Plaid Link exit
  const handleOnExit = (err, metadata) => {
    if (err) {
      setError(err.error_message || 'User exited Plaid Link');
    }

    if (onExit) {
      onExit(err, metadata);
    }
  };

  // Handle Plaid Link events
  const handleOnEvent = (eventName, metadata) => {
    console.log('Plaid Link Event:', eventName, metadata);
  };

  // Configure Plaid Link with enhanced options
  const config = {
    token: linkToken,
    onSuccess: handleOnSuccess,
    onExit: handleOnExit,
    onEvent: handleOnEvent,
  };

  // Add optional configuration
  if (longtail !== undefined) config.longtail = longtail;
  if (forceIframe) config.forceIframe = forceIframe;

  const { open, ready, exit } = usePlaidLink(config);

  if (loading) {
    return (
      <div className="plaid-loading">
        <div className="loading-spinner"></div>
        <p>Loading Plaid Link...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="plaid-error">
        <p>Error: {error}</p>
        <div className="error-actions">
          <button
            onClick={() => {
              setError(null);
              setLoading(true);
              // Retry fetching link token
              window.location.reload();
            }}
            className="btn btn-primary"
          >
            Retry
          </button>
          {exit && (
            <button
              onClick={() => exit()}
              className="btn btn-secondary"
            >
              Close
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="plaid-link-container">
      <button
        onClick={() => open()}
        disabled={!ready}
        className="btn btn-primary plaid-connect-btn"
      >
        <span className="btn-icon">🏦</span>
        {mode === 'update' ? 'Update Bank Connection' : 'Connect Bank Account'}
      </button>
      <p className="plaid-description">
        Securely connect your bank account to verify funds and access financial data.
        {institutionId && ' (Institution pre-selected)'}
        {mode === 'update' && ' (Updating existing connection)'}
      </p>
      {exit && (
        <button
          onClick={() => exit()}
          className="btn btn-link plaid-exit-btn"
        >
          Cancel Connection
        </button>
      )}
    </div>
  );
}

export default PlaidLink;
