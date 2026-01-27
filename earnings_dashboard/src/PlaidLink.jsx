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
  forceIframe = false,
  // New customization props
  countryCodes = ['US'], // Array of country codes
  language = 'en', // Language code
  user, // User object for personalization
  webhook, // Webhook URL for events
  linkCustomizationName, // Name of Link customization
  theme = 'default', // 'default', 'dark', 'light'
  buttonStyle = {}, // Custom button styles
  showInstitutionSearch = true, // Show institution search
  showInstitutionList = true, // Show institution list
  onEvent, // Additional event handler
  // Update mode specific props
  itemId, // Required for update mode
  updateModeTrigger // What triggered the update mode
}) {
  const [linkToken, setLinkToken] = useState(providedLinkToken || null);
  const [loading, setLoading] = useState(!providedLinkToken);
  const [error, setError] = useState(null);

  // Handle OAuth redirect on component mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const publicToken = urlParams.get('public_token');
    const oauthStateId = urlParams.get('oauth_state_id');

    if (publicToken) {
      // SECURITY: Validate OAuth redirect parameters
      if (!publicToken || typeof publicToken !== 'string' || publicToken.length < 10) {
        setError('Invalid OAuth redirect parameters');
        return;
      }

      // Handle OAuth redirect - exchange public token
      const handleOAuthRedirect = async () => {
        try {
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
            onSuccess(data.data, { oauth_state_id: oauthStateId });
          }

          // Clear URL params
          window.history.replaceState({}, document.title, window.location.pathname);
        } catch (err) {
          // SECURITY: Sanitize error messages to prevent XSS
          const sanitizedError = err.message ? err.message.replace(/[<>'"&]/g, '') : 'OAuth redirect failed';
          setError(sanitizedError);
        }
      };

      handleOAuthRedirect();
    }
  }, [onSuccess]);

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
        if (countryCodes) requestBody.countryCodes = countryCodes;
        if (language) requestBody.language = language;
        if (user) requestBody.user = user;
        if (webhook) requestBody.webhook = webhook;
        if (linkCustomizationName) requestBody.linkCustomizationName = linkCustomizationName;

        // Add update mode specific parameters
        if (mode === 'update') {
          if (itemId) requestBody.itemId = itemId;
          if (updateModeTrigger) requestBody.updateModeTrigger = updateModeTrigger;
        }

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
  }, [userId, products, mode, institutionId, accountFilters, paymentInitiation, redirectUri, providedLinkToken, countryCodes, language, user, webhook, linkCustomizationName]);

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
    // SECURITY: Remove sensitive data logging in production
    if (process.env.NODE_ENV !== 'production') {
      logger.info('Plaid Link Event:', { eventName, metadata: { ...metadata, account_id: '[REDACTED]' } });
    }

    // Handle specific events for error recovery
    if (eventName === 'ERROR' && metadata?.error_code === 'ITEM_LOGIN_REQUIRED') {
      logger.warn('ITEM_LOGIN_REQUIRED detected - update mode needed');
      // Could trigger update mode automatically here
    }
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
        <p>Error: {error.replace(/[<>'"&]/g, '')}</p>
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
