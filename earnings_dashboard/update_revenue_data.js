const readline = require('readline');

const revenueStreams = {
  aiLicensing: 500000000,
  autonomousSecurity: 350000000,
  medicalDiagnostics: 250000000,
  climateModeling: 200000000,
  militaryAI: 300000000,
  dataStorage: 150000000,
  strategicConsulting: 100000000,
};

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const updatedRevenue = {};

const keys = Object.keys(revenueStreams);
let index = 0;

function askNext() {
  if (index === keys.length) {
    console.log('Updated Revenue Data:');
    console.log(JSON.stringify(updatedRevenue, null, 2));
    rl.close();
    return;
  }
  const key = keys[index];
  rl.question(`Enter new value for ${key} (current: ${revenueStreams[key]}): `, (answer) => {
    const value = Number(answer);
    if (isNaN(value)) {
      console.log('Please enter a valid number.');
      askNext();
    } else {
      updatedRevenue[key] = value;
      index++;
      askNext();
    }
  });
}

console.log('Update Revenue Streams');
askNext();
