import React, { useState } from 'react';

function PrivacyConsent({ onAccept, onDecline, onViewPolicy }) {
  const [accepted, setAccepted] = useState(false);
  const [showDetails, setShowDetails] = useState(false);

  const handleAccept = () => {
    if (accepted) {
      onAccept();
    }
  };

  const handleDecline = () => {
    onDecline();
  };

  const handleViewPolicy = () => {
    if (onViewPolicy) {
      onViewPolicy();
    } else {
      // Default: open Plaid's privacy policy
      window.open('https://plaid.com/legal/', '_blank');
    }
  };

  return (
    <div className="privacy-consent-modal">
      <div className="privacy-consent-content">
        <div className="consent-header">
          <h3>Data Privacy Consent</h3>
          <p>Before connecting your bank account, please review and accept our data privacy terms.</p>
        </div>

        <div className="consent-body">
          <div className="consent-summary">
            <h4>What we collect:</h4>
            <ul>
              <li>Account balances and transaction history</li>
              <li>Account holder information</li>
              <li>Institution connection details</li>
            </ul>

            <h4>How we use your data:</h4>
            <ul>
              <li>Verify your financial information</li>
              <li>Provide personalized financial insights</li>
              <li>Process transactions and payments</li>
              <li>Improve our services</li>
            </ul>
          </div>

          <div className="consent-details-toggle">
            <button
              onClick={() => setShowDetails(!showDetails)}
              className="btn-link"
            >
              {showDetails ? 'Hide Details' : 'Show Full Privacy Policy'}
            </button>
          </div>

          {showDetails && (
            <div className="consent-details">
              <h4>Detailed Privacy Information</h4>
              <p>
                We partner with Plaid Inc. to securely connect your financial accounts.
                Plaid collects and processes your financial data according to their
                <a href="#" onClick={handleViewPolicy}> End User Privacy Policy</a>.
              </p>

              <p>
                Your data is encrypted and stored securely. We only access the information
                necessary to provide our services and comply with regulatory requirements.
              </p>

              <p>
                You can revoke access and delete your data at any time through your
                account settings. For more information, please review our complete
                privacy policy.
              </p>
            </div>
          )}

          <div className="consent-checkbox">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={accepted}
                onChange={(e) => setAccepted(e.target.checked)}
              />
              <span className="checkmark"></span>
              I consent to the collection and processing of my financial data as described above
            </label>
          </div>
        </div>

        <div className="consent-actions">
          <button
            onClick={handleDecline}
            className="btn btn-secondary"
          >
            Decline
          </button>
          <button
            onClick={handleAccept}
            disabled={!accepted}
            className="btn btn-primary"
          >
            Accept & Continue
          </button>
        </div>

        <div className="consent-footer">
          <small>
            By continuing, you agree to our terms of service and acknowledge that
            you have read and understood our privacy policy.
          </small>
        </div>
      </div>
    </div>
  );
}

export default PrivacyConsent;
