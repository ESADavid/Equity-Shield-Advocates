const fs = require('fs');
const path = require('path');

const filePath = path.resolve(__dirname, 'babel.config.cjs');

fs.access(filePath, fs.constants.F_OK, (err) => {
  if (err) {
    console.log('babel.config.cjs does not exist.');
  } else {
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error('Error deleting babel.config.cjs:', err);
      } else {
        console.log('babel.config.cjs deleted successfully.');
      }
    });
  }
});
