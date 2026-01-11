const updateRevenueData = require('./earnings_dashboard/update_revenue_data.js');

updateRevenueData().then(success => {
  console.log('Update completed:', success);
}).catch(err => {
  console.error('Error:', err);
});
