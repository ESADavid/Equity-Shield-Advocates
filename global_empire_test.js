// Global Acquisition Test
const DebtService = require('./services/debtAcquisitionService').default;
const service = new DebtService();
service.initializeDebtPortfolio();
const stacks = service.acquireGlobalDebtStacks('testuser', 'testtenant');
console.log('Global Stacks Acquired:', stacks.length);
console.log('Portfolio:', service.getDebtPortfolioAnalytics());

const FoodService = require('./services/GlobalFoodAcquisitionService').default;
const foodService = new FoodService();
foodService.initializePortfolio();
