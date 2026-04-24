// Fixed: removed unused logger import (TS6192)
// Added default logger import for test code
import logger from 'utils/loggerWrapper.js';

// Global Acquisition Test
const DebtService = require('./services/debtAcquisitionService').default;
const service = new DebtService();
service.initializeDebtPortfolio();
const stacks = service.acquireGlobalDebtStacks('testuser', 'testtenant');
logger.info('Global Stacks Acquired:', stacks.length);
logger.info('Portfolio:', service.getDebtPortfolioAnalytics());

const FoodService = require('./services/GlobalFoodAcquisitionService').default;
const foodService = new FoodService();
foodService.initializePortfolio();
logger.info('Food Empire:', foodService.getAnalytics());
