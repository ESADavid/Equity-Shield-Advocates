import { info, error, warn, debug } from '../utils/loggerWrapper.js';

const fs = require('fs');
const path = require('path');

const filePath = path.resolve(__dirname, 'babel.config.cjs');

fs.access(filePath, fs.constants.F_OK, (err) => {
  if (err) {
    logger.info('babel.config.cjs does not exist.');
  } else {
    fs.unlink(filePath, (err) => {
      if (err) {
        logger.error('Error deleting babel.config.cjs:', err);
      } else {
        logger.info('babel.config.cjs deleted successfully.');
      }
    });
  }
});
