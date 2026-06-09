// Fixed: Converted to ESM format
import logger from './utils/loggerWrapper.js';
import DebtService from './services/debtAcquisitionService.js';
import FoodService from './services/GlobalFoodAcquisitionService.js';

// Initialize Debt Service
const debtService = new DebtService();
debtService.initializeDebtPortfolio();
const stacks = debtService.acquireGlobalDebtStacks('testuser', 'testtenant');
logger.info('Global Stacks Acquired:', stacks.length);
logger.info('Portfolio:', debtService.getDebtPortfolioAnalytics());

// Initialize Food Service
const foodService = new FoodService();
foodService.initializePortfolio();
logger.info('Food Empire:', foodService.getAnalytics());

// Export for other modules
export default {
  debtService,
  foodService,
};

export { debtService, foodService };
