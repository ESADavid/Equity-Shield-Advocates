import React, { useState, useEffect } from 'react';

function WebsiteManagement({ controlStatus, onStatusUpdate }) {
  const [websites, setWebsites] = useState([]);
  const [selectedWebsite, setSelectedWebsite] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchWebsites();
  }, []);

  const fetchWebsites = async () => {
    try {
      const response = await fetch('/jpmorgan/control/websites', {
        headers: {
          'Authorization': 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
      });
      if (response.ok) {
        const data = await response.json();
        setWebsites(data.websites || []);
      }
    } catch (error) {
      console.error('Failed to fetch websites:', error);
    } finally {
      setLoading(false);
    }
  };

  const executeWebsiteAction = async (action, websiteId) => {
    try {
      const response = await fetch('/jpmorgan/control/website-action', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
        body: JSON.stringify({ action, websiteId }),
      });

      if (response.ok) {
        alert(`Action "${action}" executed successfully`);
        fetchWebsites();
        onStatusUpdate();
      } else {
        alert('Failed to execute website action');
      }
    } catch (error) {
      console.error('Failed to execute website action:', error);
      alert('Error executing website action');
    }
  };

  const updateWebsiteConfig = async (websiteId, config) => {
    try {
      const response = await fetch('/jpmorgan/control/website-config', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
        body: JSON.stringify({ websiteId, config }),
      });

      if (response.ok) {
        alert('Website configuration updated successfully');
        fetchWebsites();
      } else {
        alert('Failed to update website configuration');
      }
    } catch (error) {
      console.error('Failed to update website config:', error);
      alert('Error updating website configuration');
    }
  };

  if (loading) {
    return <div className="loading">Loading website management...</div>;
  }

  return (
    <div className="website-management">
      <div className="management-header">
        <h2>JPMorgan Website Management</h2>
        <button
          className="refresh-btn"
          onClick={fetchWebsites}
        >
          Refresh Status
        </button>
      </div>

      <div className="websites-grid">
        {websites.map(website => (
          <div key={website.id} className="website-card">
            <div className="website-header">
              <h3>{website.name}</h3>
              <span className={`status ${website.status}`}>{website.status}</span>
            </div>

            <div className="website-info">
              <div className="info-item">
                <span className="label">URL:</span>
                <span className="value">{website.url}</span>
              </div>
              <div className="info-item">
                <span className="label">Type:</span>
                <span className="value">{website.type}</span>
              </div>
              <div className="info-item">
                <span className="label">Last Access:</span>
                <span className="value">
                  {website.lastAccess ? new Date(website.lastAccess).toLocaleString() : 'Never'}
                </span>
              </div>
              <div className="info-item">
                <span className="label">Active Sessions:</span>
                <span className="value">{website.activeSessions || 0}</span>
              </div>
            </div>

            <div className="website-actions">
              <button
                className="action-btn"
                onClick={() => executeWebsiteAction('access', website.id)}
              >
                Access
              </button>
              <button
                className="action-btn"
                onClick={() => executeWebsiteAction('refresh', website.id)}
              >
                Refresh
              </button>
              <button
                className="action-btn warning"
                onClick={() => executeWebsiteAction('logout-all', website.id)}
              >
                Logout All
              </button>
              <button
                className="action-btn danger"
                onClick={() => executeWebsiteAction('block', website.id)}
              >
                Block Access
              </button>
            </div>

            <div className="website-config">
              <h4>Configuration</h4>
              <div className="config-options">
                <label>
                  <input
                    type="checkbox"
                    checked={website.config?.autoLogin || false}
                    onChange={(e) => updateWebsiteConfig(website.id, {
                      ...website.config,
                      autoLogin: e.target.checked
                    })}
                  />
                  Auto Login
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={website.config?.sessionMonitoring || false}
                    onChange={(e) => updateWebsiteConfig(website.id, {
                      ...website.config,
                      sessionMonitoring: e.target.checked
                    })}
                  />
                  Session Monitoring
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={website.config?.activityLogging || false}
                    onChange={(e) => updateWebsiteConfig(website.id, {
                      ...website.config,
                      activityLogging: e.target.checked
                    })}
                  />
                  Activity Logging
                </label>
              </div>
            </div>
          </div>
        ))}
      </div>

      {websites.length === 0 && (
        <div className="no-websites">
          <p>No JPMorgan websites configured for management.</p>
          <button
            className="setup-btn"
            onClick={() => executeWebsiteAction('setup', 'all')}
          >
            Setup Website Management
          </button>
        </div>
      )}
    </div>
  );
}

export default WebsiteManagement;
