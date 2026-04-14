import React, { useEffect, useState } from 'react';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import JPMorganControlCenter from './JPMorganControlCenter.jsx';
import WalletWebapp from './WalletWebapp.jsx';
import PlaidLink from './PlaidLink.jsx';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

function Dashboard() {
  const [earningsData, setEarningsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeView, setActiveView] = useState('earnings');
  const [connectedAccounts, setConnectedAccounts] = useState([]);

  useEffect(() => {
    if (activeView === 'earnings') {
      fetchEarnings();
    }
  }, [activeView]);

  const fetchEarnings = async () => {
    try {
      const response = await fetch('/api/earnings', {
        headers: {
          Authorization: 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setEarningsData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const renderEarningsDashboard = () => {
    if (loading)
      return <div className="loading">Loading earnings dashboard...</div>;
    if (error) return <div className="error">Error loading data: {error}</div>;

    const labels = Object.keys(earningsData.revenueStreams);
    const amounts = labels.map(
      (label) => earningsData.revenueStreams[label].amount
    );

    const data = {
      labels,
      datasets: [
        {
          label: 'Revenue',
          data: amounts,
          backgroundColor: 'rgba(75, 192, 192, 0.5)',
        },
      ],
    };

    const options = {
      responsive: true,
      plugins: {
        legend: { position: 'top' },
        title: { display: true, text: 'Earnings Dashboard' },
      },
    };

    return (
      <div className="earnings-dashboard">
        <h1>Earnings Dashboard</h1>
        <div className="wealth-growth-info">
          <p>
            <strong>Daily Growth Rate:</strong>{' '}
            {earningsData.dailyGrowthRate?.toFixed(2)}%
          </p>
          <p>
            <strong>Growth Multiplier:</strong>{' '}
            {earningsData.growthMultiplier?.toFixed(4)}x
          </p>
          <p className="wealth-message">
            💰 Your wealth increases daily! Check back tomorrow for even higher
            values.
          </p>
        </div>
        <Bar options={options} data={data} />
      </div>
    );
  };

  return (
    <div className="main-dashboard">
      <nav className="dashboard-navigation">
        <button
          className={`nav-btn ${activeView === 'earnings' ? 'active' : ''}`}
          onClick={() => setActiveView('earnings')}
        >
          Earnings Dashboard
        </button>
        <button
          className={`nav-btn ${activeView === 'control' ? 'active' : ''}`}
          onClick={() => setActiveView('control')}
        >
          JPMorgan Control Center
        </button>
        <button
          className={`nav-btn ${activeView === 'wallet' ? 'active' : ''}`}
          onClick={() => setActiveView('wallet')}
        >
          Wallet Management
        </button>
        <button
          className={`nav-btn ${activeView === 'plaid' ? 'active' : ''}`}
          onClick={() => setActiveView('plaid')}
        >
          Bank Account Connection
        </button>
      </nav>

      <main className="dashboard-content">
        {activeView === 'earnings' && renderEarningsDashboard()}
        {activeView === 'control' && <JPMorganControlCenter />}
        {activeView === 'wallet' && <WalletWebapp />}
        {activeView === 'plaid' && (
          <div className="plaid-integration-section">
            <h1>Bank Account Connection</h1>
            <p>
              Connect your bank accounts securely using Plaid for proof of funds
              verification and income analysis.
            </p>
            <PlaidLink
              userId="oscar-broome-user"
              products={['transactions', 'balances', 'income']}
              onSuccess={(data, metadata) => {
                console.log('Plaid Link Success:', data, metadata);
                if (data && data.accounts) {
                  setConnectedAccounts(data.accounts);
                }
                alert('Bank account connected successfully!');
              }}
              onExit={(err, metadata) => {
                console.log('Plaid Link Exit:', err, metadata);
                if (err) {
                  alert('Connection cancelled or failed');
                }
              }}
            />
            {connectedAccounts.length > 0 && (
              <div className="connected-accounts">
                <h2>Connected Accounts</h2>
                <ul>
                  {connectedAccounts.map((account, index) => (
                    <li key={index}>
                      <strong>{account.name}</strong> - {account.type} (
                      {account.subtype}) - Balance: ${account.balances.current}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

export default Dashboard;
