import React, { useState, useEffect } from 'react';
import { usePlaidLink } from 'react-plaid-link';




function LayerOnboarding({
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
}) {
  const [sessionToken, setSessionToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [phoneNumber, setPhoneNumber] = useState('');
  /** @type {string} */
  const [dateOfBirth, setDateOfBirth] = useState('');
  /** @type {'phone' | 'dob' | 'layer'} */
  const [currentStep, setCurrentStep] = useState('phone');
  /** @type {'ready' | 'not_available' | 'autofill_not_available' | null} */
  const [layerEligibility, setLayerEligibility] = useState(null);

  // Handle Layer events
  const handleOnEvent = (eventName, metadata) => {
    switch (eventName) {
      case 'LAYER_READY':
        setLayerEligibility('ready');
        setCurrentStep('layer');
        if (onLayerReady) onLayerReady(metadata || {});
        break;
      case 'LAYER_NOT_AVAILABLE':
        setLayerEligibility('not_available');
        setCurrentStep('dob');
        if (onLayerNotAvailable) onLayerNotAvailable(metadata || {});
        break;
      case 'LAYER_AUTOFILL_NOT_AVAILABLE':
        setLayerEligibility('autofill_not_available');
        if (onLayerAutofillNotAvailable) onLayerAutofillNotAvailable(metadata || {});
        break;
      default:
        if (onLayerEvent) onLayerEvent(eventName, metadata);
    }
  };

  // Handle success
  const handleOnSuccess = async (publicToken, metadata) => {
    try {
      const response = await fetch('/api/plaid/exchange-public-token', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ publicToken }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Failed to exchange token');
      if (onSuccess) onSuccess(data.data, metadata);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error');
    }
  };

  const handleOnExit = (err, metadata) => {
    if (err) setError(err.error_message || 'User exited');
    if (onExit) onExit(err, metadata);
  };

  useEffect(() => {
    if (!userId || !templateId) return setLoading(false);

    fetch('/api/plaid/layer/session-token', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({templateId, userId, clientName, webhook, linkCustomizationName}),
    })
      .then(res => res.json())
      .then(data => {
        if (data.error) throw new Error(data.message);
        setSessionToken(data.data.session_token);
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [userId, templateId, clientName, webhook, linkCustomizationName]);

  const handlePhoneSubmit = (e) => {
    e.preventDefault();
    if (!phoneNumber || !sessionToken) return;

    try {
      const Plaid = window.Plaid;
      const handler = Plaid.create({
        token: sessionToken,
        onSuccess: handleOnSuccess,
        onExit: handleOnExit,
        onEvent: handleOnEvent
      });
      handler.submit({ phone_number: phoneNumber });
      window.layerHandler = handler;
    } catch (err) {
      setError('Failed to initialize Layer');
    }
  };

  const handleDOBSubmit = (e) => {
    e.preventDefault();
    if (!dateOfBirth || !window.layerHandler) return;
    try {
      window.layerHandler.submit({ date_of_birth: dateOfBirth });
    } catch (err) {
      setError('Failed to submit DOB');
    }
  };

  const handleOpenLayer = () => {
    if (window.layerHandler) window.layerHandler.open();
  };

  const retry = () => {
    setError(null);
    setLoading(true);
    window.location.reload();
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
        <button onClick={retry} className="btn btn-primary">Retry</button>
      </div>
    );
  }

  return (
    <div className="layer-onboarding-container">
      {currentStep === 'phone' && (
        <div className="layer-phone-step">
          <h3>Instant Account Verification</h3>
          <p>Enter your phone number to instantly verify your identity and connect your accounts.</p>
          <form onSubmit={handlePhoneSubmit} className="layer-form">
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
              />
            </div>
            <button type="submit" className="btn btn-primary layer-submit-btn" disabled={!phoneNumber || !sessionToken}>
              Continue with Phone Number
            </button>
          </form>
        </div>
      )}

      {currentStep === 'dob' && layerEligibility === 'not_available' && (
        <div className="layer-dob-step">
          <h3>Additional Verification</h3>
          <p>Your phone number isn't eligible for instant verification. Provide your date of birth for extended verification.</p>
          <form onSubmit={handleDOBSubmit} className="layer-form">
            <div className="form-group">
              <label htmlFor="dob">Date of Birth</label>
              <input
                type="date"
                id="dob"
                value={dateOfBirth}
                onChange={(e) => setDateOfBirth(e.target.value)}
                required
                className="form-control"
              />
            </div>
            <button type="submit" className="btn btn-primary layer-submit-btn" disabled={!dateOfBirth}>
              Continue with Date of Birth
            </button>
          </form>
          <p className="layer-alternative">
            Or <button type="button" className="btn-link" onClick={() => setCurrentStep('phone')}>try a different phone number</button>
          </p>
        </div>
      )}

      {currentStep === 'layer' && layerEligibility === 'ready' && (
        <div className="layer-ready-step">
          <h3>Ready to Connect</h3>
          <p>Your information has been verified! Click below to securely connect your accounts.</p>
          <button onClick={handleOpenLayer} className="btn btn-success layer-connect-btn">
            <span className="btn-icon">🔒</span> Connect Accounts Securely
          </button>
        </div>
      )}

      {layerEligibility === 'autofill_not_available' && (
        <div className="layer-fallback">
          <h3>Alternative Verification Required</h3>
          <p>Extended verification not available. Use standard process.</p>
          <button onClick={retry} className="btn btn-secondary">
            Use Standard Connection
          </button>
        </div>
      )}

      <div className="layer-info">
        <p className="layer-security-note">
          🔒 Your data is encrypted and secure. Bank-level security.
        </p>
      </div>
    </div>
  );
}

export default LayerOnboarding;

