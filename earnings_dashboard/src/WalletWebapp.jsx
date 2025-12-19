import React, { useState, useEffect } from 'react';
import './WalletWebapp.css';

function WalletWebapp() {
  const [activeTab, setActiveTab] = useState('decrypt');
  const [formData, setFormData] = useState({});
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Pre-populate with OWLBAN GROUP and OSCAR BROOME wallet data
  const owlbanWalletData = {
    cardNumber: '4111111111111111',
    expiryMonth: '12',
    expiryYear: '2025',
    cvv: '123',
    cardholderName: 'OWLBAN GROUP',
    accountNumber: '123456789012',
    routingNumber: '021000021',
  };

  const oscarBroomeWalletData = {
    cardNumber: '5555555555554444',
    expiryMonth: '06',
    expiryYear: '2026',
    cvv: '456',
    cardholderName: 'OSCAR BROOME',
    accountNumber: '987654321098',
    routingNumber: '021000021',
  };

  useEffect(() => {
    // Initialize form data based on active tab
    switch (activeTab) {
      case 'encrypt':
        setFormData({
          cardNumber: '',
          expiryMonth: '',
          expiryYear: '',
          cvv: '',
          cardholderName: '',
          accountNumber: '',
          routingNumber: '',
        });
        break;
      case 'decrypt':
        setFormData({ encryptedWalletData: '' });
        break;
      case 'validate':
        setFormData({ walletData: '' });
        break;
      case 'tokenize':
        setFormData({ sensitiveData: '' });
        break;
      case 'detokenize':
        setFormData({ token: '' });
        break;
      default:
        setFormData({});
    }
    setResult(null);
    setError(null);
  }, [activeTab]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const loadOwlbanWallet = () => {
    setFormData(owlbanWalletData);
  };

  const loadOscarBroomeWallet = () => {
    setFormData(oscarBroomeWalletData);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let endpoint = '';
      let payload = {};

      switch (activeTab) {
        case 'encrypt':
          endpoint = '/api/jpmorgan/wallet-encrypt';
          payload = formData;
          break;
        case 'decrypt':
          endpoint = '/api/jpmorgan/wallet-decrypt';
          payload = { encryptedWalletData: formData.encryptedWalletData };
          break;
        case 'validate':
          endpoint = '/api/jpmorgan/wallet-validate';
          payload = { walletData: formData.walletData };
          break;
        case 'tokenize':
          endpoint = '/api/jpmorgan/wallet-tokenize';
          payload = { sensitiveData: formData.sensitiveData };
          break;
        case 'detokenize':
          endpoint = '/api/jpmorgan/wallet-detokenize';
          payload = { token: formData.token };
          break;
        default:
          throw new Error('Invalid operation');
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `HTTP error! status: ${response.status}`);
      }

      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const renderForm = () => {
    switch (activeTab) {
      case 'encrypt':
        return (
          <div className="wallet-form">
            <div className="wallet-section">
              <h2>Encrypt Wallet Data</h2>
              <p>
                Enter card and account information to generate secure encrypted
                wallet data.
              </p>

              <div className="wallet-presets">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={loadOwlbanWallet}
                >
                  Load OWLBAN GROUP Wallet
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={loadOscarBroomeWallet}
                >
                  Load OSCAR BROOME Wallet
                </button>
              </div>

              <form onSubmit={handleSubmit}>
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="cardNumber">Card Number</label>
                    <input
                      type="text"
                      id="cardNumber"
                      name="cardNumber"
                      value={formData.cardNumber || ''}
                      onChange={handleInputChange}
                      placeholder="4111111111111111"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="cvv">CVV</label>
                    <input
                      type="text"
                      id="cvv"
                      name="cvv"
                      value={formData.cvv || ''}
                      onChange={handleInputChange}
                      placeholder="123"
                      required
                    />
                  </div>
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="expiryMonth">Expiry Month</label>
                    <input
                      type="text"
                      id="expiryMonth"
                      name="expiryMonth"
                      value={formData.expiryMonth || ''}
                      onChange={handleInputChange}
                      placeholder="12"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="expiryYear">Expiry Year</label>
                    <input
                      type="text"
                      id="expiryYear"
                      name="expiryYear"
                      value={formData.expiryYear || ''}
                      onChange={handleInputChange}
                      placeholder="2025"
                      required
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label htmlFor="cardholderName">Cardholder Name</label>
                  <input
                    type="text"
                    id="cardholderName"
                    name="cardholderName"
                    value={formData.cardholderName || ''}
                    onChange={handleInputChange}
                    placeholder="JOHN DOE"
                    required
                  />
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="accountNumber">Account Number</label>
                    <input
                      type="text"
                      id="accountNumber"
                      name="accountNumber"
                      value={formData.accountNumber || ''}
                      onChange={handleInputChange}
                      placeholder="123456789012"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="routingNumber">Routing Number</label>
                    <input
                      type="text"
                      id="routingNumber"
                      name="routingNumber"
                      value={formData.routingNumber || ''}
                      onChange={handleInputChange}
                      placeholder="021000021"
                      required
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading}
                >
                  {loading ? 'Encrypting...' : 'Encrypt Wallet Data'}
                </button>
              </form>
            </div>
          </div>
        );

      case 'decrypt':
        return (
          <div className="wallet-form">
            <div className="wallet-section">
              <h2>Decrypt Wallet Data</h2>
              <p>
                Paste encrypted wallet data to retrieve original card
                information.
              </p>

              <form onSubmit={handleSubmit}>
                <div className="form-group">
                  <label htmlFor="encryptedWalletData">
                    Encrypted Wallet Data
                  </label>
                  <textarea
                    id="encryptedWalletData"
                    name="encryptedWalletData"
                    value={formData.encryptedWalletData || ''}
                    onChange={handleInputChange}
                    placeholder="Paste encrypted wallet data here..."
                    rows="6"
                    required
                  />
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading}
                >
                  {loading ? 'Decrypting...' : 'Decrypt Wallet Data'}
                </button>
              </form>
            </div>
          </div>
        );

      case 'validate':
        return (
          <div className="wallet-form">
            <div className="wallet-section">
              <h2>Validate Wallet Data</h2>
              <p>
                Check if wallet data meets security and compliance standards.
              </p>

              <form onSubmit={handleSubmit}>
                <div className="form-group">
                  <label htmlFor="walletData">Wallet Data (JSON)</label>
                  <textarea
                    id="walletData"
                    name="walletData"
                    value={formData.walletData || ''}
                    onChange={handleInputChange}
                    placeholder='{"cardNumber": "4111111111111111", "cvv": "123", ...}'
                    rows="8"
                    required
                  />
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading}
                >
                  {loading ? 'Validating...' : 'Validate Wallet Data'}
                </button>
              </form>
            </div>
          </div>
        );

      case 'tokenize':
        return (
          <div className="wallet-form">
            <div className="wallet-section">
              <h2>Tokenize Sensitive Data</h2>
              <p>Convert sensitive payment data into secure tokens.</p>

              <form onSubmit={handleSubmit}>
                <div className="form-group">
                  <label htmlFor="sensitiveData">Sensitive Data</label>
                  <textarea
                    id="sensitiveData"
                    name="sensitiveData"
                    value={formData.sensitiveData || ''}
                    onChange={handleInputChange}
                    placeholder="Enter sensitive data to tokenize..."
                    rows="4"
                    required
                  />
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading}
                >
                  {loading ? 'Tokenizing...' : 'Create Token'}
                </button>
              </form>
            </div>
          </div>
        );

      case 'detokenize':
        return (
          <div className="wallet-form">
            <div className="wallet-section">
              <h2>Detokenize Data</h2>
              <p>Retrieve original data from a secure token.</p>

              <form onSubmit={handleSubmit}>
                <div className="form-group">
                  <label htmlFor="token">Token</label>
                  <input
                    type="text"
                    id="token"
                    name="token"
                    value={formData.token || ''}
                    onChange={handleInputChange}
                    placeholder="Enter token to detokenize..."
                    required
                  />
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading}
                >
                  {loading ? 'Detokenizing...' : 'Detokenize Data'}
                </button>
              </form>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  const renderResult = () => {
    if (!result && !error) return null;

    if (error) {
      return (
        <div className="result-section error">
          <h3>❌ Error</h3>
          <div className="error-content">
            <p>{error}</p>
          </div>
        </div>
      );
    }

    return (
      <div className="result-section success">
        <h3>✅ Success</h3>
        <div className="result-content">
          <div className="code-block">
            <pre>{JSON.stringify(result, null, 2)}</pre>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="wallet-webapp">
      <div className="wallet-header">
        <h1>JPMorgan Wallet Management</h1>
        <p>Secure wallet operations for OWLBAN GROUP and OSCAR BROOME</p>
      </div>

      <div className="wallet-container">
        <nav className="tab-navigation">
          <button
            className={`tab-btn ${activeTab === 'decrypt' ? 'active' : ''}`}
            onClick={() => setActiveTab('decrypt')}
          >
            <span className="tab-icon">🔓</span> Decrypt
          </button>
          <button
            className={`tab-btn ${activeTab === 'encrypt' ? 'active' : ''}`}
            onClick={() => setActiveTab('encrypt')}
          >
            <span className="tab-icon">🔒</span> Encrypt
          </button>
          <button
            className={`tab-btn ${activeTab === 'validate' ? 'active' : ''}`}
            onClick={() => setActiveTab('validate')}
          >
            <span className="tab-icon">✓</span> Validate
          </button>
          <button
            className={`tab-btn ${activeTab === 'tokenize' ? 'active' : ''}`}
            onClick={() => setActiveTab('tokenize')}
          >
            <span className="tab-icon">🎫</span> Tokenize
          </button>
          <button
            className={`tab-btn ${activeTab === 'detokenize' ? 'active' : ''}`}
            onClick={() => setActiveTab('detokenize')}
          >
            <span className="tab-icon">🔄</span> Detokenize
          </button>
        </nav>

        <div className="tab-content">
          {renderForm()}
          {renderResult()}
        </div>
      </div>
    </div>
  );
}

export default WalletWebapp;
