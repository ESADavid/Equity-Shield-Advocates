(async () => {
  const { getAnalytics } = await import('./earnings_dashboard/ai_analytics.js');
  const { getTranscendenceAnalytics, optimizeRevenueAutonomously } =
    await import('./earnings_dashboard/ai_transcendence.js');

  console.log('Testing Simple Trend Analytics...');
  try {
    const analytics = getAnalytics();
    console.log('Analytics result:', JSON.stringify(analytics, null, 2));
  } catch (error) {
    console.error('Analytics error:', error);
  }

  console.log('\nTesting Simple Revenue Forecasting...');
  try {
    const transcendence = getTranscendenceAnalytics();
    console.log('Forecasting result:', JSON.stringify(transcendence, null, 2));
  } catch (error) {
    console.error('Forecasting error:', error);
  }

  console.log('\nTesting Traditional Revenue Optimization...');
  try {
    const result = await optimizeRevenueAutonomously(1750000, {
      growth: 0.08,
      volatility: 0.15,
      competition: 0.2,
      regulation: 0.1,
    });
    console.log('Optimization result:', JSON.stringify(result, null, 2));
  } catch (error) {
    console.error('Optimization error:', error);
  }
})();
