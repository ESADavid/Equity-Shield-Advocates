import React, { useState, useEffect } from 'react';

function ControlDashboard({ controlStatus, onStatusUpdate }) {
  const [systemMetrics, setSystemMetrics] = useState(null);
  const [recentActivities, setRecentActivities] = useState([]);

  useEffect(() => {
    fetchSystemMetrics();
    fetchRecentActivities();
  }, []);

  const fetchSystemMetrics = async () => {
    try {
      const response = await fetch('/jpmorgan/control/metrics', {
        headers: {
          Authorization: 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
      });
      if (response.ok) {
        const data = await response.json();
        setSystemMetrics(data);
      }
    } catch (error) {
      console.error('Failed to fetch system metrics:', error);
    }
  };

  const fetchRecentActivities = async () => {
    try {
      const response = await fetch('/jpmorgan/control/activities', {
        headers: {
          Authorization: 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
      });
      if (response.ok) {
        const data = await response.json();
        setRecentActivities(data.activities || []);
      }
    } catch (error) {
      console.error('Failed to fetch recent activities:', error);
    }
  };

  const executeControlAction = async (action, target) => {
    try {
      const response = await fetch('/jpmorgan/control/execute', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
        },
        body: JSON.stringify({ action, target }),
      });

      if (response.ok) {
        alert(`Action "${action}" executed successfully on ${target}`);
        onStatusUpdate();
        fetchRecentActivities();
      } else {
        alert('Failed to execute action');
      }
    } catch (error) {
      console.error('Failed to execute control action:', error);
      alert('Error executing action');
    }
  };

  return (
    <div className="control-dashboard">
      <div className="dashboard-grid">
        {/* System Status Overview */}
        <div className="status-card">
          <h3>System Status Overview</h3>
          <div className="status-indicators">
            <div className="indicator">
              <span className="label">Payment Systems:</span>
              <span
                className={`status ${controlStatus?.paymentStatus || 'unknown'}`}
              >
                {controlStatus?.paymentStatus || 'Unknown'}
              </span>
            </div>
            <div className="indicator">
              <span className="label">Treasury Services:</span>
              <span
                className={`status ${controlStatus?.treasuryStatus || 'unknown'}`}
              >
                {controlStatus?.treasuryStatus || 'Unknown'}
              </span>
            </div>
            <div className="indicator">
              <span className="label">Website Access:</span>
              <span
                className={`status ${controlStatus?.websiteStatus || 'unknown'}`}
              >
                {controlStatus?.websiteStatus || 'Unknown'}
              </span>
            </div>
            <div className="indicator">
              <span className="label">Private Banking:</span>
              <span
                className={`status ${controlStatus?.bankingStatus || 'unknown'}`}
              >
                {controlStatus?.bankingStatus || 'Unknown'}
              </span>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="actions-card">
          <h3>Quick Actions</h3>
          <div className="action-buttons">
            <button
              className="action-btn primary"
              onClick={() => executeControlAction('sync', 'all')}
            >
              Sync All Systems
            </button>
            <button
              className="action-btn secondary"
              onClick={() => executeControlAction('health-check', 'all')}
            >
              Health Check
            </button>
            <button
              className="action-btn warning"
              onClick={() => executeControlAction('reset', 'cache')}
            >
              Clear Cache
            </button>
            <button
              className="action-btn danger"
              onClick={() => executeControlAction('emergency-stop', 'all')}
            >
              Emergency Stop
            </button>
            <button
              className="action-btn ai"
              style={{
                background: 'linear-gradient(45deg, #8B5CF6, #06B6D4)',
                color: 'white',
              }}
              onClick={async () => {
                try {
                  const response = await fetch('/api/multi-agent/optimize', {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      Authorization:
                        'Basic ' + btoa('BSEAN4890@GMAIL.COM:TBROOME704'),
                    },
                    body: JSON.stringify({
                      prompt: 'Optimize revenue systems for divine efficiency',
                    }),
                  });
                  const result = await response.json();
                  if (result.success) {
                    alert(
                      `🤖 Blackbox AI task created: ${result.taskId}\nMonitor: ${result.taskUrl}`
                    );
                  } else {
                    alert(
                      'AI task failed: ' + (result.error || 'Unknown error')
                    );
                  }
                } catch (error) {
                  alert('AI integration error: ' + error.message);
                }
              }}
            >
              🤖 AI Multi-Agent Optimize
            </button>
          </div>
        </div>

        {/* System Metrics */}
        <div className="metrics-card">
          <h3>System Metrics</h3>
          {systemMetrics ? (
            <div className="metrics-grid">
              <div className="metric">
                <span className="value">
                  {systemMetrics.totalTransactions || 0}
                </span>
                <span className="label">Total Transactions</span>
              </div>
              <div className="metric">
                <span className="value">
                  {systemMetrics.activeConnections || 0}
                </span>
                <span className="label">Active Connections</span>
              </div>
              <div className="metric">
                <span className="value">{systemMetrics.uptime || '0%'}</span>
                <span className="label">System Uptime</span>
              </div>
              <div className="metric">
                <span className="value">{systemMetrics.errorRate || '0%'}</span>
                <span className="label">Error Rate</span>
              </div>
            </div>
          ) : (
            <div className="loading">Loading metrics...</div>
          )}
        </div>

        {/* Recent Activities */}
        <div className="activities-card">
          <h3>Recent Activities</h3>
          <div className="activities-list">
            {recentActivities.length > 0 ? (
              recentActivities.slice(0, 10).map((activity, index) => (
                <div key={index} className="activity-item">
                  <span className="timestamp">
                    {new Date(activity.timestamp).toLocaleString()}
                  </span>
                  <span className="action">{activity.action}</span>
                  <span className="target">{activity.target}</span>
                  <span className={`status ${activity.status}`}>
                    {activity.status}
                  </span>
                </div>
              ))
            ) : (
              <div className="no-activities">No recent activities</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default ControlDashboard;
