import React, { useEffect, useState } from 'react';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import JPMorganControlCenter from './JPMorganControlCenter.jsx';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

function Dashboard() {
  const [earningsData, setEarningsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeView, setActiveView] = useState('earnings');

  useEffect(() => {
    if (activeView === 'earnings') {
      fetchEarnings();
    }
  }, [activeView]);

  const fetchEarnings = async () => {
    try {
      const response = await fetch('/api/earnings', {
        headers: {
          'Authorization': 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
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
    if (loading) return <div className="loading">Loading earnings dashboard...</div>;
    if (error) return <div className="error">Error loading data: {error}</div>;

    const labels = Object.keys(earningsData.revenueStreams);
    const amounts = labels.map(label => earningsData.revenueStreams[label].amount);

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
      </nav>

      <main className="dashboard-content">
        {activeView === 'earnings' ? renderEarningsDashboard() : <JPMorganControlCenter />}
      </main>
    </div>
  );
}

export default Dashboard;
