import React, { useState, useEffect } from 'react';
import WebsiteManagement from './WebsiteManagement.jsx';
import PrivateBankingControls from './PrivateBankingControls.jsx';
import ControlDashboard from './ControlDashboard.jsx';
import './ControlCenter.css';

function JPMorganControlCenter() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [controlStatus, setControlStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchControlStatus();
  }, []);

  const fetchControlStatus = async () => {
    try {
      const response = await fetch('/jpmorgan/control/status', {
        headers: {
          'Authorization': 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
      });
      if (response.ok) {
        const data = await response.json();
        setControlStatus(data);
      }
    } catch (error) {
      console.error('Failed to fetch control status:', error);
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'dashboard', label: 'Control Dashboard', component: ControlDashboard },
    { id: 'websites', label: 'Website Management', component: WebsiteManagement },
    { id: 'banking', label: 'Private Banking', component: PrivateBankingControls },
  ];

  const ActiveComponent = tabs.find(tab => tab.id === activeTab)?.component || ControlDashboard;

  if (loading) {
    return (
      <div className="jpmorgan-control-center">
        <div className="loading">Loading JPMorgan Control Center...</div>
      </div>
    );
  }

  return (
    <div className="jpmorgan-control-center">
      <header className="control-header">
        <h1>JPMorgan Control Center</h1>
        <div className="status-indicator">
          <span className={`status ${controlStatus?.overallStatus || 'unknown'}`}>
            Status: {controlStatus?.overallStatus || 'Unknown'}
          </span>
        </div>
      </header>

      <nav className="control-navigation">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="control-content">
        <ActiveComponent controlStatus={controlStatus} onStatusUpdate={fetchControlStatus} />
      </main>
    </div>
  );
}

export default JPMorganControlCenter;
