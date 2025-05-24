const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const basicAuth = require('express-basic-auth');

const app = express();
const PORT = 4000;

// Basic authentication setup
app.use(basicAuth({
  users: { 'admin': 'securepassword' },
  challenge: true,
}));

app.use(cors());
app.use(express.json());

// Use the existing revenue.json file path
const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

function getEarningsData() {
  if (!fs.existsSync(revenueDataPath)) {
    return null;
  }
  const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
  return {
    totalAnnualRevenue: data.totalRevenue,
    totalDailyRevenue: data.totalRevenue / 365,
    revenueStreams: {
      sampleRepo: {
        amount: data.totalRevenue,
        accountNumber: 'N/A',
      },
    },
  };
}

app.get('/api/earnings', (req, res) => {
  const earnings = getEarningsData();
  if (!earnings) {
    return res.status(404).json({ error: 'Earnings data not found' });
  }
  res.json(earnings);
});

app.get('/api/earnings/download', (req, res) => {
  const earnings = getEarningsData();
  if (!earnings) {
    return res.status(404).json({ error: 'Earnings data not found' });
  }
  res.setHeader('Content-Disposition', 'attachment; filename="earnings_report.json"');
  res.json(earnings);
});

app.get('/', (req, res) => {
  const html = [
    '<html>',
    '<head><title>OWLban Earnings Dashboard</title></head>',
    '<body>',
    '<h1>OWLban Earnings Dashboard</h1>',
    '<div id="earnings"></div>',
    '<script>',
    'async function fetchEarnings() {',
    '  const response = await fetch("/api/earnings", { headers: { "Authorization": "Basic " + btoa("admin:securepassword") } });',
    '  if (!response.ok) {',
    '    document.getElementById("earnings").innerText = "Failed to load earnings data";',
    '    return;',
    '  }',
    '  const data = await response.json();',
    '  let html = "<h2>Total Annual Revenue: $" + data.totalAnnualRevenue.toLocaleString() + "</h2>";',
    '  html += "<h3>Total Daily Revenue: $" + data.totalDailyRevenue.toFixed(2) + "</h3>";',
    '  html += "<ul>";',
    '  for (const [stream, details] of Object.entries(data.revenueStreams)) {',
    '    html += "<li>" + stream + ": $" + details.amount.toLocaleString() + " (Account: " + details.accountNumber + ")</li>";',
    '  }',
    '  html += "</ul>";',
    '  document.getElementById("earnings").innerHTML = html;',
    '}',
    'fetchEarnings();',
    '</script>',
    '</body>',
    '</html>'
  ].join("");
  res.send(html);
});

const server = app.listen(PORT, () => {
  console.log(`Earnings dashboard running at http://localhost:${PORT}`);
});

module.exports = { app, server };
