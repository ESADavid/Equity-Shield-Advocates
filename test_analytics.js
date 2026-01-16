import { getAnalytics } from './earnings_dashboard/ai_analytics.js';
import {
  getSimpleAnalytics,
  optimizeRevenueAutonomously,
} from './earnings_dashboard/ai_transcendence.js';

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('Testing Simple Analytics...');
  try {
    const analytics = getAnalytics();
    console.log('Analytics result:', JSON.stringify(analytics, null, 2));
  } catch (error) {
    console.error('Analytics error:', error);
  }

  console.log('\nTesting Simple Revenue Optimization...');
  try {
    const transcendence = getSimpleAnalytics();
    console.log(
      'Optimization result:',
      JSON.stringify(transcendence, null, 2)
    );
  } catch (error) {
    console.error('Optimization error:', error);
  }

  console.log('\nTesting Revenue Optimization...');
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
}
