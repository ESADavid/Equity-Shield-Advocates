import React, { useState, useEffect } from 'react';

function PrivateBankingControls({ controlStatus, onStatusUpdate }) {
  const [accounts, setAccounts] = useState([]);
  const [selectedAccount, setSelectedAccount] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showTransferModal, setShowTransferModal] = useState(false);
  const [transferData, setTransferData] = useState({
    fromAccount: '',
    toAccount: '',
    amount: '',
    currency: 'USD',
    description: ''
  });

  useEffect(() => {
    fetchAccounts();
  }, []);

  const fetchAccounts = async () => {
    try {
      const response = await fetch('/jpmorgan/control/banking/accounts', {
        headers: {
          'Authorization': 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
      });
      if (response.ok) {
        const data = await response.json();
        setAccounts(data.accounts || []);
      }
    } catch (error) {
      console.error('Failed to fetch banking accounts:', error);
    } finally {
      setLoading(false);
    }
  };

  const executeBankingAction = async (action, accountId, params = {}) => {
    try {
      const response = await fetch('/jpmorgan/control/banking-action', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
        body: JSON.stringify({ action, accountId, ...params }),
      });

      if (response.ok) {
        alert(`Banking action "${action}" executed successfully`);
        fetchAccounts();
        onStatusUpdate();
      } else {
        alert('Failed to execute banking action');
      }
    } catch (error) {
      console.error('Failed to execute banking action:', error);
      alert('Error executing banking action');
    }
  };

  const handleTransfer = async () => {
    if (!transferData.fromAccount || !transferData.toAccount || !transferData.amount) {
      alert('Please fill in all transfer details');
      return;
    }

    await executeBankingAction('transfer', null, transferData);
    setShowTransferModal(false);
    setTransferData({
      fromAccount: '',
      toAccount: '',
      amount: '',
      currency: 'USD',
      description: ''
    });
  };

  if (loading) {
    return <div className="loading">Loading private banking controls...</div>;
  }

  return (
    <div className="private-banking-controls">
      <div className="banking-header">
        <h2>Private Banking Controls</h2>
        <div className="header-actions">
          <button
            className="action-btn primary"
            onClick={() => setShowTransferModal(true)}
          >
            New Transfer
          </button>
          <button
            className="refresh-btn"
            onClick={fetchAccounts}
          >
            Refresh Accounts
          </button>
        </div>
      </div>

      <div className="accounts-overview">
        <div className="overview-stats">
          <div className="stat">
            <span className="value">{accounts.length}</span>
            <span className="label">Total Accounts</span>
          </div>
          <div className="stat">
            <span className="value">
              {accounts.reduce((sum, acc) => sum + (acc.balance || 0), 0).toLocaleString()}
            </span>
            <span className="label">Total Balance (USD)</span>
          </div>
          <div className="stat">
            <span className="value">
              {accounts.filter(acc => acc.status === 'active').length}
            </span>
            <span className="label">Active Accounts</span>
          </div>
        </div>
      </div>

      <div className="accounts-grid">
        {accounts.map(account => (
          <div key={account.id} className="account-card">
            <div className="account-header">
              <h3>{account.name}</h3>
              <span className={`status ${account.status}`}>{account.status}</span>
            </div>

            <div className="account-details">
              <div className="detail-row">
                <span className="label">Account Number:</span>
                <span className="value">****{account.number?.slice(-4)}</span>
              </div>
              <div className="detail-row">
                <span className="label">Type:</span>
                <span className="value">{account.type}</span>
              </div>
              <div className="detail-row">
                <span className="label">Balance:</span>
                <span className="value">
                  {account.currency} {account.balance?.toLocaleString()}
                </span>
              </div>
              <div className="detail-row">
                <span className="label">Available:</span>
                <span className="value">
                  {account.currency} {account.availableBalance?.toLocaleString()}
                </span>
              </div>
              <div className="detail-row">
                <span className="label">Last Transaction:</span>
                <span className="value">
                  {account.lastTransaction ? new Date(account.lastTransaction).toLocaleString() : 'None'}
                </span>
              </div>
            </div>

            <div className="account-actions">
              <button
                className="action-btn"
                onClick={() => executeBankingAction('view-transactions', account.id)}
              >
                View Transactions
              </button>
              <button
                className="action-btn"
                onClick={() => executeBankingAction('statement', account.id)}
              >
                Download Statement
              </button>
              <button
                className="action-btn warning"
                onClick={() => executeBankingAction('freeze', account.id)}
              >
                Freeze Account
              </button>
              <button
                className="action-btn danger"
                onClick={() => executeBankingAction('close', account.id)}
              >
                Close Account
              </button>
            </div>

            <div className="account-settings">
              <h4>Account Settings</h4>
              <div className="settings-options">
                <label>
                  <input
                    type="checkbox"
                    checked={account.settings?.autoTransfer || false}
                    onChange={(e) => executeBankingAction('update-setting', account.id, {
                      setting: 'autoTransfer',
                      value: e.target.checked
                    })}
                  />
                  Auto Transfer
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={account.settings?.alerts || false}
                    onChange={(e) => executeBankingAction('update-setting', account.id, {
                      setting: 'alerts',
                      value: e.target.checked
                    })}
                  />
                  Transaction Alerts
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={account.settings?.onlineBanking || false}
                    onChange={(e) => executeBankingAction('update-setting', account.id, {
                      setting: 'onlineBanking',
                      value: e.target.checked
                    })}
                  />
                  Online Banking
                </label>
              </div>
            </div>
          </div>
        ))}
      </div>

      {accounts.length === 0 && (
        <div className="no-accounts">
          <p>No private banking accounts configured.</p>
          <button
            className="setup-btn"
            onClick={() => executeBankingAction('setup-accounts', null)}
          >
            Setup Banking Accounts
          </button>
        </div>
      )}

      {/* Transfer Modal */}
      {showTransferModal && (
        <div className="modal-overlay">
          <div className="modal">
            <h3>Transfer Funds</h3>
            <div className="modal-content">
              <div className="form-group">
                <label>From Account:</label>
                <select
                  value={transferData.fromAccount}
                  onChange={(e) => setTransferData({...transferData, fromAccount: e.target.value})}
                >
                  <option value="">Select account</option>
                  {accounts.map(acc => (
                    <option key={acc.id} value={acc.id}>
                      {acc.name} - {acc.currency} {acc.availableBalance?.toLocaleString()}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>To Account:</label>
                <select
                  value={transferData.toAccount}
                  onChange={(e) => setTransferData({...transferData, toAccount: e.target.value})}
                >
                  <option value="">Select account</option>
                  {accounts.map(acc => (
                    <option key={acc.id} value={acc.id}>
                      {acc.name} - {acc.currency} {acc.availableBalance?.toLocaleString()}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>Amount:</label>
                <input
                  type="number"
                  value={transferData.amount}
                  onChange={(e) => setTransferData({...transferData, amount: e.target.value})}
                  placeholder="Enter amount"
                />
              </div>

              <div className="form-group">
                <label>Currency:</label>
                <select
                  value={transferData.currency}
                  onChange={(e) => setTransferData({...transferData, currency: e.target.value})}
                >
                  <option value="USD">USD</option>
                  <option value="EUR">EUR</option>
                  <option value="GBP">GBP</option>
                  <option value="JPY">JPY</option>
                </select>
              </div>

              <div className="form-group">
                <label>Description:</label>
                <textarea
                  value={transferData.description}
                  onChange={(e) => setTransferData({...transferData, description: e.target.value})}
                  placeholder="Transfer description"
                />
              </div>
            </div>

            <div className="modal-actions">
              <button className="cancel-btn" onClick={() => setShowTransferModal(false)}>
                Cancel
              </button>
              <button className="confirm-btn" onClick={handleTransfer}>
                Execute Transfer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default PrivateBankingControls;
