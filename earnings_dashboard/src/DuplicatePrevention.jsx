import React, { useState, useEffect } from 'react';

function DuplicatePrevention({
  userId,
  onItemSelected,
  onNewItemRequested,
  existingItems = [],
  institutionId,
  accountFilters,
  showExistingConnections = true,
  allowNewConnections = true
}) {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState([]);
  const [selectedItem, setSelectedItem] = useState(null);
  const [error, setError] = useState(null);

  // Fetch existing items for the user
  useEffect(() => {
    const fetchExistingItems = async () => {
      try {
        setLoading(true);
        const response = await fetch(`/api/plaid/items?userId=${userId}`);
        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.message || 'Failed to fetch existing items');
        }

        setItems(data.data || []);
      } catch (err) {
        console.error('Error fetching existing items:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    if (userId) {
      fetchExistingItems();
    }
  }, [userId]);

  // Filter items by institution if specified
  const filteredItems = institutionId
    ? items.filter(item => item.institutionId === institutionId)
    : items;

  const handleItemSelect = (item) => {
    setSelectedItem(item);
    if (onItemSelected) {
      onItemSelected(item);
    }
  };

  const handleNewConnection = () => {
    if (onNewItemRequested) {
      onNewItemRequested();
    }
  };

  const getInstitutionName = (item) => {
    return item.institution?.name || item.institutionName || 'Unknown Institution';
  };

  const getAccountSummary = (item) => {
    const accounts = item.accounts || [];
    const accountTypes = [...new Set(accounts.map(acc => acc.type))];
    return `${accounts.length} account${accounts.length !== 1 ? 's' : ''} (${accountTypes.join(', ')})`;
  };

  if (loading) {
    return (
      <div className="duplicate-prevention-loading">
        <div className="loading-spinner"></div>
        <p>Loading existing connections...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="duplicate-prevention-error">
        <p>Error loading existing connections: {error}</p>
        <button onClick={() => window.location.reload()} className="btn btn-secondary">
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="duplicate-prevention-container">
      <div className="duplicate-prevention-header">
        <h3>🔍 Check Existing Connections</h3>
        <p>
          {institutionId
            ? `You already have connections to ${getInstitutionName(filteredItems[0] || {})}. Select an existing connection or create a new one.`
            : 'Select an existing bank connection or connect a new account.'
          }
        </p>
      </div>

      {showExistingConnections && filteredItems.length > 0 && (
        <div className="existing-connections">
          <h4>Existing Connections</h4>
          <div className="connections-list">
            {filteredItems.map((item) => (
              <div
                key={item.id}
                className={`connection-item ${selectedItem?.id === item.id ? 'selected' : ''}`}
                onClick={() => handleItemSelect(item)}
              >
                <div className="connection-info">
                  <div className="institution-name">
                    🏦 {getInstitutionName(item)}
                  </div>
                  <div className="account-summary">
                    {getAccountSummary(item)}
                  </div>
                  <div className="connection-status">
                    <span className={`status-indicator ${item.status || 'active'}`}>
                      {item.status === 'error' ? '⚠️ Error' :
                       item.status === 'pending' ? '⏳ Pending' : '✅ Active'}
                    </span>
                    <span className="last-updated">
                      Updated: {item.lastUpdated ? new Date(item.lastUpdated).toLocaleDateString() : 'Unknown'}
                    </span>
                  </div>
                </div>
                <div className="connection-actions">
                  <button
                    className="btn btn-primary select-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleItemSelect(item);
                    }}
                  >
                    Use This Connection
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {allowNewConnections && (
        <div className="new-connection-section">
          <div className="new-connection-divider">
            <span>or</span>
          </div>

          <div className="new-connection-option">
            <div className="new-connection-info">
              <h4>Connect New Account</h4>
              <p>Link a new bank account or connect to a different institution.</p>
            </div>
            <button
              onClick={handleNewConnection}
              className="btn btn-secondary new-connection-btn"
            >
              🔗 Connect New Account
            </button>
          </div>
        </div>
      )}

      {filteredItems.length === 0 && (
        <div className="no-existing-connections">
          <p>No existing connections found. Ready to connect your first account!</p>
          <button
            onClick={handleNewConnection}
            className="btn btn-primary"
          >
            Get Started
          </button>
        </div>
      )}

      <div className="duplicate-prevention-footer">
        <small>
          💡 Tip: Reusing existing connections is faster and more secure than creating duplicates.
        </small>
      </div>
    </div>
  );
}

export default DuplicatePrevention;
