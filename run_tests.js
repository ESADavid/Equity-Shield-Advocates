const { exec } = require('child_process');

exec(
  'npx jest earnings_dashboard/server.test.fixed.js --verbose --config="{\\"testMatch\\":[\\"**/earnings_dashboard/**/*.test.js\\"]}"',
  (error, stdout, stderr) => {
    if (error) {
      console.error(`Error executing tests: ${error.message}`);
      return;
    }
    if (stderr) {
      console.error(`Test stderr: ${stderr}`);
    }
    console.log(`Test output:\n${stdout}`);
  }
);
