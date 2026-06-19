import React, { useState, useEffect, useCallback } from 'react';
// Removed unused usePlaidLink import

// LayerOnboarding component - Plain JSX version
const LayerOnboarding = ({
  onSuccess,
  onExit,
  userId,
  templateId,
  onLayerReady,
  onLayerNotAvailable,
  onLayerAutofillNotAvailable,
  onLayerEvent,
  clientName = '',
  webhook = '',
  linkCustomizationName = '',
  buttonStyle = {},
  theme = 'default',
}) => {
  const [sessionToken, setSessionToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [phoneNumber, setPhoneNumber] = useState('');
  const [dateOfBirth, setDateOfBirth] = useState('');
  const [currentStep, setCurrentStep] = useState('phone');
  const [layerEligibility, setLayerEligibility] = useState(null);

  // Handle Layer events
  const handleOnEvent = useCallback((eventName, metadata) => {
    switch (eventName) {
      case 'LAYER_READY':
        setLayerEligibility('ready');
        setCurrentStep('layer');
        if (onLayerReady) onLayerReady(metadata);
        break;
      case 'LAYER_NOT_AVAILABLE':
        setLayerEligibility('not_available');
        setCurrentStep('dob');
        if (onLayerNotAvailable) onLayerNotAvailable(metadata);
        break;
      case 'LAYER_AUTOFILL_NOT_AVAILABLE':
        setLayerEligibility('autofill_not_available');
        if (onLayerAutofillNotAvailable) onLayerAutofillNotAvailable(metadata);
        break;
      default:
        if (onLayerEvent) onLayerEvent(eventName, metadata);
    }
  }, [onLayerReady, onLayerNotAvailable, onLayerAutofillNotAvailable, onLayerEvent]);

  // Handle success
  const handleOnSuccess = useCallback(async (publicToken, metadata) => {
    try {
      const response = await fetch('/api/plaid/exchange-public-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ publicToken }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || data.error || 'Failed to exchange token');
      }
      
      onSuccess(data.data, metadata);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
    }
  }, [onSuccess]);

  const handleOnExitCallback = useCallback((err, metadata) => {
    if (err && err.error_message) {
      setError(err.error_message);
    }
    onExit(err, metadata);
  }, [onExit]);

  useEffect(() => {
    if (!userId || !templateId) {
      setLoading(false);
      return;
    }

    fetch('/api/plaid/layer/session-token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        templateId, 
        userId, 
        clientName, 
        webhook, 
        linkCustomizationName 
      }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          throw new Error(data.message || data.error);
        }
        setSessionToken(data.data.session_token);
      })
      .catch((err) => {
        const errorMessage = err instanceof Error ? err.message : 'Failed to initialize';
        setError(errorMessage);
      })
      .finally(() => setLoading(false));
  }, [userId, templateId, clientName, webhook, linkCustomizationName]);

  const handlePhoneSubmit = (e) => {
    e.preventDefault();
    if (!phoneNumber || !sessionToken) return;

    try {
      if (typeof globalThis !== 'undefined' && globalThis.Plaid) {
        const Plaid = window.Plaid;
        const handler = Plaid.create({
          token: sessionToken,
          onSuccess: handleOnSuccess,
          onExit: handleOnExitCallback,
          onEvent: handleOnEvent
        });
        handler.submit({ phone_number: phoneNumber });
        globalThis.layerHandler = handler;
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to initialize Layer';
      setError(errorMessage);
    }
  };

  const handleDOBSubmit = (e) => {
    e.preventDefault();
    if (!dateOfBirth || !globalThis.layerHandler) return;
    
    try {
      window.layerHandler.submit({ date_of_birth: dateOfBirth });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to submit DOB';
      setError(errorMessage);
    }
  };

  const handleOpenLayer = () => {
    if (globalThis.layerHandler) {
      window.layerHandler.open();
    }
  };

  const retry = () => {
    setError(null);
    setLoading(true);
    if (typeof globalThis !== 'undefined') {
      globalThis.location.reload();
    }
  };

  if (loading) {
    return (
      <div className="layer-loading">
        <div className="loading-spinner"></div>
        <p>Initializing Layer...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="layer-error">
        <p>Error: {error}</p>
        <button 
          type="button"
          onClick={retry} 
          className="btn btn-primary"
          aria-label="Retry Layer initialization"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="layer-onboarding-container" role="main">
      {currentStep === 'phone' && (
        <div className="layer-phone-step">
          <h3>Instant Account Verification</h3>
          <p>Enter your phone number to instantly verify your identity and connect your accounts.</p>
          <form onSubmit={handlePhoneSubmit} className="layer-form" noValidate>
            <div className="form-group">
              <label htmlFor="phone">Phone Number</label>
              <input
                type="tel"
                id="phone"
                value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
                placeholder="+1 (555) 123-4567"
                required
                className="form-control"
                aria-describedby="phone-help"
              />
              <small id="phone-help" className="form-text text-muted">
                We'll send a secure verification code
              </small>
            </div>
            <button 
              type="submit" 
              className="btn btn-primary layer-submit-btn" 
              disabled={!phoneNumber || !sessionToken}
              aria-label="Continue with phone verification"
            >
              Continue with Phone Number
            </button>
          </form>
        </div>
      )}

      {currentStep === 'dob' && layerEligibility === 'not_available' && (
        <div className="layer-dob-step">
          <h3>Additional Verification</h3>
          <p>Your phone number isn't eligible for instant verification. Provide your date of birth for extended verification.</p>
          <form onSubmit={handleDOBSubmit} className="layer-form" noValidate>
            <div className="form-group">
              <label htmlFor="dob">Date of Birth</label>
              <input
                type="date"
                id="dob"
                value={dateOfBirth}
                onChange={(e) => setDateOfBirth(e.target.value)}
                required
                max={new Date().toISOString().split('T')[0]}
                className="form-control"
              />
            </div>
            <button 
              type="submit" 
              className="btn btn-primary layer-submit-btn" 
              disabled={!dateOfBirth}
            >
              Continue with Date of Birth
            </button>
          </form>
          <p className="layer-alternative">
            Or{' '}
            <button 
              type="button" 
              className="btn-link" 
              onClick={() => setCurrentStep('phone')}
            >
              try a different phone number
            </button>
          </p>
        </div>
      )}

      {currentStep === 'layer' && layerEligibility === 'ready' && (
        <div className="layer-ready-step">
          <h3>Ready to Connect</h3>
          <p>Your information has been verified! Click below to securely connect your accounts.</p>
          <button 
            type="button"
            onClick={handleOpenLayer} 
            className="btn btn-success layer-connect-btn"
            aria-label="Connect bank accounts securely"
          >
            <span className="btn-icon" aria-hidden="true">🔒</span>
            Connect Accounts Securely
          </button>
        </div>
      )}

      {layerEligibility === 'autofill_not_available' && (
        <div className="layer-fallback">
          <h3>Alternative Verification Required</h3>
          <p>Extended verification not available. Use standard process.</p>
          <button 
            type="button"
            onClick={retry} 
            className="btn btn-secondary"
          >
            Use Standard Connection
          </button>
        </div>
      )}

      <div className="layer-info" aria-live="polite">
        <p className="layer-security-note">
          🔒 Your data is encrypted and secure. Bank-level security.
        </p>
      </div>
    </div>
  );
};

export default LayerOnboarding;
