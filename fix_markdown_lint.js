import { info, error, warn, debug } from 'utils/loggerWrapper.js';

const fs = require('fs');

// Read the file
let content = fs.readFileSync(
  'KING_SACHEM_YOCHANAN_PERSONAL_WEALTH_CONTROL_SYSTEM.md',
  'utf8'
);

// Fix MD012: Remove multiple consecutive blank lines
content = content.replace(/\n\n\n+/g, '\n\n');

// Fix MD009: Remove trailing spaces
content = content.replace(/ +$/gm, '');

// Fix MD034: Wrap bare URLs in angle brackets
content = content.replace(
  /^- URL: https:\/\/wealth\.kingsachemyochanan\.com$/m,
  '- URL: <https://wealth.kingsachemyochanan.com>'
);
content = content.replace(
  /^- Or emergency\.kingsachemyochanan\.com$/m,
  '- Or <emergency.kingsachemyochanan.com>'
);

// Fix MD036: Convert bold text to headings at specific lines
// These are the "Scenario" bold texts that should be headings
content = content.replace(
  /\n\n\*\*Scenario 1: Buy Anything\*\*\n/g,
  '\n\n### Scenario 1: Buy Anything\n'
);
content = content.replace(
  /\n\n\*\*Scenario 2: Help Someone\*\*\n/g,
  '\n\n### Scenario 2: Help Someone\n'
);
content = content.replace(
  /\n\n\*\*Scenario 3: Invest\*\*\n/g,
  '\n\n### Scenario 3: Invest\n'
);
content = content.replace(
  /\n\n\*\*Scenario 4: Emergency Cash\*\*\n/g,
  '\n\n### Scenario 4: Emergency Cash\n'
);

// Write the file back
fs.writeFileSync(
  'KING_SACHEM_YOCHANAN_PERSONAL_WEALTH_CONTROL_SYSTEM.md',
  content,
  'utf8'
);

logger.info('Fixed all markdownlint errors!');
