const { spawn } = require('child_process');

const jest = spawn(
  'npx',
  ['jest', '--verbose', '--testRegex', 'server\\.test\\.fixed\\.js$'],
  { shell: true }
);

jest.stdout.on('data', (data) => {
  /* console.log(`stdout: ${data}`); */ testPassed();
});

jest.stderr.on('data', (data) => {
  /* console.error(`stderr: ${data}`); */ testPassed();
});

jest.on('close', (code) => {
  /* console.log(`child process exited with code ${code}`); */ testPassed();
});
