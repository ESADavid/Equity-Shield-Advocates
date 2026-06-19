import React, { useState, useEffect } from 'react';
import WebsiteManagement from './WebsiteManagement.jsx';
import PrivateBankingControls from './PrivateBankingControls.jsx';
import ControlDashboard from './ControlDashboard.jsx';
import './ControlCenter.css';

function JPMorganControlCenter() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [controlStatus, setControlStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isMobile, setIsMobile] = useState(false);
  const [showMobileMenu, setShowMobileMenu] = useState(false);

  useEffect(() => {
    fetchControlStatus();
    checkMobileDevice();

    // Add resize listener for mobile detection
    const handleResize = () => checkMobileDevice();
    window.addEventListener('resize', handleResize);

    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const checkMobileDevice = () => {
    setIsMobile(window.innerWidth <= 768);
  };

  const fetchControlStatus = async () => {
    try {
      const response = await fetch('/jpmorgan/control/status', {
        headers: {
          Authorization: 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
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
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: '📊',
      component: ControlDashboard,
    },
    {
      id: 'banking',
      label: 'Banking',
      icon: '🏦',
      component: PrivateBankingControls,
    },
    {
      id: 'websites',
      label: 'Websites',
      icon: '🌐',
      component: WebsiteManagement,
    },
  ];

  const ActiveComponent =
    tabs.find((tab) => tab.id === activeTab)?.component || ControlDashboard;

  const handleTabChange = (tabId) => {
    setActiveTab(tabId);
    if (isMobile) {
      setShowMobileMenu(false);
    }
  };

  if (loading) {
    return (
      <div className="jpmorgan-control-center">
        <div className="loading">
          <div className="loading-spinner"></div>
          <p>Loading JPMorgan Control Center...</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`jpmorgan-control-center ${isMobile ? 'mobile' : ''}`}>
      <header className="control-header">
        <div className="header-content">
          <h1>JPMorgan Control Center</h1>
          {isMobile && (
            <button
              className="mobile-menu-toggle"
              onClick={() => setShowMobileMenu(!showMobileMenu)}
              aria-label="Toggle menu"
            >
              {showMobileMenu ? '✕' : '☰'}
            </button>
          )}
        </div>
        <div className="status-indicator">
          <span
            className={`status ${controlStatus?.overallStatus || 'unknown'}`}
          >
            {isMobile ? '●' : 'Status:'}{' '}
            {controlStatus?.overallStatus || 'Unknown'}
          </span>
        </div>
      </header>

      <nav
        className={`control-navigation ${isMobile ? 'mobile' : ''} ${showMobileMenu ? 'open' : ''}`}
      >
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`nav-tab ${activeTab === tab.id ? 'active' : ''} ${isMobile ? 'mobile' : ''}`}
            onClick={() => handleTabChange(tab.id)}
          >
            {isMobile && tab.icon} {tab.label}
          </button>
        ))}
      </nav>

      <main className={`control-content ${isMobile ? 'mobile' : ''}`}>
        <ActiveComponent
          controlStatus={controlStatus}
          onStatusUpdate={fetchControlStatus}
          isMobile={isMobile}
        />
      </main>

      {/* Mobile overlay for menu */}
      {isMobile && showMobileMenu && (
        <button
          className="mobile-overlay"
          onClick={() => setShowMobileMenu(false)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              setShowMobileMenu(false);
            }
          }}
          aria-label="Close mobile menu"
          type="button"
        ></button>
      )}
    </div>
  );
}

export default JPMorganControlCenter;
