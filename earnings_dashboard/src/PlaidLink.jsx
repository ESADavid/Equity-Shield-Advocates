import React, { useState, useEffect } from 'react';
import { usePlaidLink } from 'react-plaid-link';

function PlaidLink({ onSuccess, onExit, userId, products = ['transactions', 'balances'] }) {
  const [linkToken, setLinkToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch link token from backend
  useEffect(() => {
    const fetchLinkToken = async () => {
      try {
        const response = await fetch('/api/plaid/create-link-token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            userId: userId || 'user_default',
            products: products,
          }),
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
  }, [userId, products]);

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

  // Configure Plaid Link
  const config = {
    token: linkToken,
    onSuccess: handleOnSuccess,
    onExit: handleOnExit,
  };

  const { open, ready } = usePlaidLink(config);

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
        Connect Bank Account
      </button>
      <p className="plaid-description">
        Securely connect your bank account to verify funds and access financial data.
      </p>
    </div>
  );
}

export default PlaidLink;
