/**
 * HEAVEN ON EARTH DASHBOARD
 * Comprehensive admin interface for managing UBI, Education, Private Military, and Compliance
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import React, { useState, useEffect } from 'react';
import axios from 'axios';

const HeavenOnEarthDashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [ubiStats, setUbiStats] = useState(null);
  const [educationStats, setEducationStats] = useState(null);
  const [complianceStats, setComplianceStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch all statistics on component mount
  useEffect(() => {
    fetchAllStatistics();
    // Refresh every 30 seconds
    const interval = setInterval(fetchAllStatistics, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchAllStatistics = async () => {
    try {
      setLoading(true);
      
      const [ubiResponse, educationResponse] = await Promise.all([
        axios.get('/api/ubi/statistics'),
        axios.get('/api/education/statistics')
      ]);

      setUbiStats(ubiResponse.data.statistics);
      setEducationStats(educationResponse.data.statistics);
      
      setError(null);
    } catch (err) {
      setError(err.message);
      console.error('Error fetching statistics:', err);
    } finally {
      setLoading(false);
    }
  };

  const processMonthlyPayments = async () => {
    if (!confirm('Process monthly UBI payments for all eligible citizens?')) return;
    
    try {
      setLoading(true);
      const response = await axios.post('/api/ubi/process-monthly-payments');
      alert(`Success! Processed ${response.data.summary.successful} payments totaling $${response.data.summary.totalAmount.toLocaleString()}`);
      fetchAllStatistics();
    } catch (err) {
      alert(`Error: ${err.response?.data?.error || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const initializeEducationPrograms = async () => {
    if (!confirm('Initialize default education programs?')) return;
    
    try {
      setLoading(true);
      const response = await axios.post('/api/education/initialize-defaults');
      alert(`Success! Initialized ${response.data.programs.length} programs`);
      fetchAllStatistics();
    } catch (err) {
      alert(`Error: ${err.response?.data?.error || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount);
  };

  return (
    <div style={styles.container}>
      {/* Header */}
      <header style={styles.header}>
        <h1 style={styles.title}>✨ HEAVEN ON EARTH ✨</h1>
        <p style={styles.subtitle}>OWLBAN GROUP - Divine Mission Control Center</p>
        <p style={styles.mission}>$33,000/year for every citizen + Mandatory Education for All</p>
      </header>

      {/* Navigation Tabs */}
      <nav style={styles.nav}>
        <button 
          style={{...styles.tab, ...(activeTab === 'overview' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button 
          style={{...styles.tab, ...(activeTab === 'ubi' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('ubi')}
        >
          💰 UBI System
        </button>
        <button 
          style={{...styles.tab, ...(activeTab === 'education' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('education')}
        >
          🎓 Education
        </button>
        <button 
          style={{...styles.tab, ...(activeTab === 'military' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('military')}
        >
          🎖️ Private Military
        </button>
        <button 
          style={{...styles.tab, ...(activeTab === 'compliance' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('compliance')}
        >
          📋 Compliance
        </button>
      </nav>

      {/* Main Content */}
      <main style={styles.main}>
        {loading && <div style={styles.loading}>Loading...</div>}
        {error && <div style={styles.error}>Error: {error}</div>}

        {/* Overview Tab */}
        {activeTab === 'overview' && !loading && (
          <div style={styles.content}>
            <h2>System Overview</h2>
            
            <div style={styles.grid}>
              {/* UBI Overview Card */}
              <div style={styles.card}>
                <h3>💰 Universal Basic Income</h3>
                {ubiStats && (
                  <>
                    <p><strong>Total Citizens:</strong> {ubiStats.citizens.total.toLocaleString()}</p>
                    <p><strong>Eligible:</strong> {ubiStats.citizens.eligible.toLocaleString()}</p>
                    <p><strong>Eligibility Rate:</strong> {ubiStats.citizens.eligibilityRate}</p>
                    <p><strong>Monthly Budget:</strong> {formatCurrency(ubiStats.payments.monthlyBudget)}</p>
                    <p><strong>Annual Budget:</strong> {formatCurrency(ubiStats.payments.annualBudget)}</p>
                    <p><strong>Per Citizen:</strong> {formatCurrency(ubiStats.amounts.perCitizen.annual)}/year</p>
                  </>
                )}
              </div>

              {/* Education Overview Card */}
              <div style={styles.card}>
                <h3>🎓 Education System</h3>
                {educationStats && (
                  <>
                    <p><strong>Total Programs:</strong> {educationStats.programs.total}</p>
                    <p><strong>Active Programs:</strong> {educationStats.programs.active}</p>
                    <p><strong>Total Enrollments:</strong> {educationStats.enrollments.total.toLocaleString()}</p>
                    <p><strong>Completed:</strong> {educationStats.enrollments.completed.toLocaleString()}</p>
                    <p><strong>Completion Rate:</strong> {educationStats.enrollments.completionRate}</p>
                    <p><strong>Certifications Issued:</strong> {educationStats.certifications.issued.toLocaleString()}</p>
                  </>
                )}
              </div>

              {/* Compliance Overview Card */}
              <div style={styles.card}>
                <h3>📋 Compliance Status</h3>
                {ubiStats && (
                  <>
                    <p><strong>Compliant Citizens:</strong> {educationStats?.citizens.compliant.toLocaleString() || 0}</p>
                    <p><strong>In Progress:</strong> {educationStats?.citizens.inProgress.toLocaleString() || 0}</p>
                    <p><strong>Non-Compliant:</strong> {educationStats?.citizens.nonCompliant.toLocaleString() || 0}</p>
                    <p><strong>Compliance Rate:</strong> {educationStats?.citizens.complianceRate || '0%'}</p>
                    <p><strong>Suspended:</strong> {ubiStats.citizens.suspended.toLocaleString()}</p>
                  </>
                )}
              </div>

              {/* Strategic Partners Card */}
              <div style={styles.card}>
                <h3>🎖️ Strategic Partners</h3>
                <p><strong>Private Military Contractors:</strong> 5</p>
                <p><strong>Personnel Deployed:</strong> 2,350</p>
                <p><strong>Contract Value:</strong> $1.87B</p>
                <p><strong>Joint Force (Burkina Faso):</strong> 5,000</p>
                <p><strong>Total Military Force:</strong> 23,000+</p>
                <p><strong>Technology Partners:</strong> NVIDIA, Microsoft, Google</p>
              </div>
            </div>

            {/* Quick Actions */}
            <div style={styles.actions}>
              <h3>Quick Actions</h3>
              <button style={styles.actionButton} onClick={processMonthlyPayments}>
                💰 Process Monthly UBI Payments
              </button>
              <button style={styles.actionButton} onClick={initializeEducationPrograms}>
                🎓 Initialize Education Programs
              </button>
              <button style={styles.actionButton} onClick={fetchAllStatistics}>
                🔄 Refresh Statistics
              </button>
            </div>
          </div>
        )}

        {/* UBI Tab */}
        {activeTab === 'ubi' && !loading && (
          <div style={styles.content}>
            <h2>💰 Universal Basic Income System</h2>
            {ubiStats && (
              <>
                <div style={styles.statsGrid}>
                  <div style={styles.statCard}>
                    <h4>Total Citizens</h4>
                    <p style={styles.bigNumber}>{ubiStats.citizens.total.toLocaleString()}</p>
                  </div>
                  <div style={styles.statCard}>
                    <h4>Eligible Citizens</h4>
                    <p style={styles.bigNumber}>{ubiStats.citizens.eligible.toLocaleString()}</p>
                  </div>
                  <div style={styles.statCard}>
                    <h4>Suspended</h4>
                    <p style={styles.bigNumber}>{ubiStats.citizens.suspended.toLocaleString()}</p>
                  </div>
                  <div style={styles.statCard}>
                    <h4>Eligibility Rate</h4>
                    <p style={styles.bigNumber}>{ubiStats.citizens.eligibilityRate}</p>
                  </div>
                </div>

                <div style={styles.section}>
                  <h3>Payment Information</h3>
                  <p><strong>Per Citizen (Monthly):</strong> {formatCurrency(ubiStats.amounts.perCitizen.monthly)}</p>
                  <p><strong>Per Citizen (Annual):</strong> {formatCurrency(ubiStats.amounts.perCitizen.annual)}</p>
                  <p><strong>Total Monthly Budget:</strong> {formatCurrency(ubiStats.payments.monthlyBudget)}</p>
                  <p><strong>Total Annual Budget:</strong> {formatCurrency(ubiStats.payments.annualBudget)}</p>
                  <p><strong>Total Disbursed:</strong> {formatCurrency(ubiStats.payments.totalDisbursed)}</p>
                </div>

                <button style={styles.primaryButton} onClick={processMonthlyPayments}>
                  Process Monthly Payments
                </button>
              </>
            )}
          </div>
        )}

        {/* Education Tab */}
        {activeTab === 'education' && !loading && (
          <div style={styles.content}>
            <h2>🎓 Education System</h2>
            {educationStats && (
              <>
                <div style={styles.section}>
                  <h3>Programs</h3>
                  <p><strong>Total Programs:</strong> {educationStats.programs.total}</p>
                  <p><strong>Active Programs:</strong> {educationStats.programs.active}</p>
                  <p><strong>Military Programs:</strong> {educationStats.programs.byType?.military || 0}</p>
                  <p><strong>Law Programs:</strong> {educationStats.programs.byType?.law || 0}</p>
                  <p><strong>Tech Programs:</strong> {educationStats.programs.byType?.tech || 0}</p>
                  <p><strong>Agriculture Programs:</strong> {educationStats.programs.byType?.agriculture || 0}</p>
                </div>

                <div style={styles.section}>
                  <h3>Enrollments & Completions</h3>
                  <p><strong>Total Enrollments:</strong> {educationStats.enrollments.total.toLocaleString()}</p>
                  <p><strong>Completed:</strong> {educationStats.enrollments.completed.toLocaleString()}</p>
                  <p><strong>Completion Rate:</strong> {educationStats.enrollments.completionRate}</p>
                  <p><strong>Certifications Issued:</strong> {educationStats.certifications.issued.toLocaleString()}</p>
                </div>

                <div style={styles.section}>
                  <h3>Citizen Compliance</h3>
                  <p><strong>Compliant:</strong> {educationStats.citizens.compliant.toLocaleString()}</p>
                  <p><strong>In Progress:</strong> {educationStats.citizens.inProgress.toLocaleString()}</p>
                  <p><strong>Non-Compliant:</strong> {educationStats.citizens.nonCompliant.toLocaleString()}</p>
                  <p><strong>Compliance Rate:</strong> {educationStats.citizens.complianceRate}</p>
                </div>

                <button style={styles.primaryButton} onClick={initializeEducationPrograms}>
                  Initialize Default Programs
                </button>
              </>
            )}
          </div>
        )}

        {/* Private Military Tab */}
        {activeTab === 'military' && !loading && (
          <div style={styles.content}>
            <h2>🎖️ Private Military Contractors</h2>
            
            <div style={styles.section}>
              <h3>PMC Contractors</h3>
              <ul style={styles.list}>
                <li><strong>Academi</strong> (formerly Blackwater) - 500 personnel - $500M contract</li>
                <li><strong>G4S Secure Solutions</strong> - 800 personnel - $400M contract</li>
                <li><strong>DynCorp International</strong> - 400 personnel - $350M contract</li>
                <li><strong>Triple Canopy</strong> - 300 personnel - $300M contract</li>
                <li><strong>Aegis Defence Services</strong> - 350 personnel - $320M contract</li>
              </ul>
            </div>

            <div style={styles.statsGrid}>
              <div style={styles.statCard}>
                <h4>Total PMCs</h4>
                <p style={styles.bigNumber}>5</p>
              </div>
              <div style={styles.statCard}>
                <h4>Personnel Deployed</h4>
                <p style={styles.bigNumber}>2,350</p>
              </div>
              <div style={styles.statCard}>
                <h4>Contract Value</h4>
                <p style={styles.bigNumber}>$1.87B</p>
              </div>
              <div style={styles.statCard}>
                <h4>Joint Force Total</h4>
                <p style={styles.bigNumber}>23,000+</p>
              </div>
            </div>

            <div style={styles.section}>
              <h3>Joint Military Force</h3>
              <p><strong>Haiti Navy:</strong> 5,000 personnel</p>
              <p><strong>Haiti Army:</strong> 15,000 personnel</p>
              <p><strong>Haiti Air Force:</strong> 3,000 personnel</p>
              <p><strong>Burkina Faso Joint Force:</strong> 5,000 personnel</p>
              <p><strong>PMC Contractors:</strong> 2,350 personnel</p>
              <p><strong>Total Combined Force:</strong> 30,350 personnel</p>
            </div>
          </div>
        )}

        {/* Compliance Tab */}
        {activeTab === 'compliance' && !loading && (
          <div style={styles.content}>
            <h2>📋 Compliance Monitoring</h2>
            
            <div style={styles.section}>
              <h3>Compliance Rules</h3>
              <ul style={styles.list}>
                <li>Citizens must complete all 4 education tracks within 24 months</li>
                <li>Failure to comply results in UBI suspension</li>
                <li>Grace period: 30 days</li>
                <li>Medical/hardship exemptions available</li>
                <li>Progress checkpoints every 3 months</li>
              </ul>
            </div>

            {educationStats && (
              <div style={styles.statsGrid}>
                <div style={styles.statCard}>
                  <h4>Compliant</h4>
                  <p style={styles.bigNumber}>{educationStats.citizens.compliant.toLocaleString()}</p>
                </div>
                <div style={styles.statCard}>
                  <h4>In Progress</h4>
                  <p style={styles.bigNumber}>{educationStats.citizens.inProgress.toLocaleString()}</p>
                </div>
                <div style={styles.statCard}>
                  <h4>Non-Compliant</h4>
                  <p style={styles.bigNumber}>{educationStats.citizens.nonCompliant.toLocaleString()}</p>
                </div>
                <div style={styles.statCard}>
                  <h4>Compliance Rate</h4>
                  <p style={styles.bigNumber}>{educationStats.citizens.complianceRate}</p>
                </div>
              </div>
            )}

            <div style={styles.section}>
              <h3>Mandatory Education Tracks</h3>
              <ul style={styles.list}>
                <li><strong>Military Training:</strong> 6 months - Combat, discipline, leadership</li>
                <li><strong>Law Education:</strong> 4 months - Constitutional law, civil rights</li>
                <li><strong>Technology Training:</strong> 6 months - Programming, AI, cybersecurity</li>
                <li><strong>Agriculture Training:</strong> 4 months - Sustainable farming, hydroponics</li>
              </ul>
              <p><strong>Total Required:</strong> 20 months</p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer style={styles.footer}>
        <p>OWLBAN GROUP - House of David | Heaven on Earth Initiative</p>
        <p>Last Updated: {new Date().toLocaleString()}</p>
      </footer>
    </div>
  );
};

// Styles
const styles = {
  container: {
    fontFamily: 'Arial, sans-serif',
    maxWidth: '1400px',
    margin: '0 auto',
    padding: '20px',
    backgroundColor: '#f5f5f5'
  },
  header: {
    textAlign: 'center',
    padding: '30px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    color: 'white',
    borderRadius: '10px',
    marginBottom: '20px'
  },
  title: {
    fontSize: '48px',
    margin: '0 0 10px 0',
    fontWeight: 'bold'
  },
  subtitle: {
    fontSize: '24px',
    margin: '0 0 10px 0'
  },
  mission: {
    fontSize: '18px',
    margin: '0',
    opacity: 0.9
  },
  nav: {
    display: 'flex',
    gap: '10px',
    marginBottom: '20px',
    flexWrap: 'wrap'
  },
  tab: {
    padding: '12px 24px',
    border: 'none',
    backgroundColor: 'white',
    cursor: 'pointer',
    borderRadius: '5px',
    fontSize: '16px',
    transition: 'all 0.3s'
  },
  activeTab: {
    backgroundColor: '#667eea',
    color: 'white',
    fontWeight: 'bold'
  },
  main: {
    minHeight: '500px'
  },
  content: {
    backgroundColor: 'white',
    padding: '30px',
    borderRadius: '10px',
    boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
    gap: '20px',
    marginTop: '20px'
  },
  card: {
    padding: '20px',
    backgroundColor: '#f9f9f9',
    borderRadius: '8px',
    border: '1px solid #e0e0e0'
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '15px',
    marginTop: '20px'
  },
  statCard: {
    padding: '20px',
    backgroundColor: '#f0f4ff',
    borderRadius: '8px',
    textAlign: 'center',
    border: '2px solid #667eea'
  },
  bigNumber: {
    fontSize: '36px',
    fontWeight: 'bold',
    color: '#667eea',
    margin: '10px 0'
  },
  section: {
    marginTop: '30px',
    paddingTop: '20px',
    borderTop: '2px solid #e0e0e0'
  },
  list: {
    lineHeight: '2',
    fontSize: '16px'
  },
  actions: {
    marginTop: '30px',
    padding: '20px',
    backgroundColor: '#f9f9f9',
    borderRadius: '8px'
  },
  actionButton: {
    padding: '12px 24px',
    margin: '5px',
    backgroundColor: '#667eea',
    color: 'white',
    border: 'none',
    borderRadius: '5px',
    cursor: 'pointer',
    fontSize: '16px',
    fontWeight: 'bold',
    transition: 'all 0.3s'
  },
  primaryButton: {
    padding: '15px 30px',
    backgroundColor: '#667eea',
    color: 'white',
    border: 'none',
    borderRadius: '5px',
    cursor: 'pointer',
    fontSize: '18px',
    fontWeight: 'bold',
    marginTop: '20px'
  },
  loading: {
    textAlign: 'center',
    padding: '50px',
    fontSize: '24px',
    color: '#667eea'
  },
  error: {
    padding: '20px',
    backgroundColor: '#ffebee',
    color: '#c62828',
    borderRadius: '5px',
    marginBottom: '20px'
  },
  footer: {
    textAlign: 'center',
    marginTop: '40px',
    padding: '20px',
    color: '#666',
    borderTop: '2px solid #e0e0e0'
  }
};

export default HeavenOnEarthDashboard;
