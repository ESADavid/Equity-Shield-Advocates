const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const basicAuth = require('express-basic-auth');

const app = express();
const PORT = process.env.PORT || 4000;

/* Removed basic authentication to allow direct access without sign-in */
app.use(cors());
app.use(express.json());

app.use(cors());
app.use(express.json());

// Use the existing revenue.json file path
const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

function readRevenueData() {
  if (!fs.existsSync(revenueDataPath)) {
    return null;
  }
  const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
  // Initialize purchase data if not present
  if (!data.purchases) {
    data.purchases = {
      corporateHomes: 0,
      autoFleet: 0
    };
  }
  return data;
}

function writeRevenueData(data) {
  fs.writeFileSync(revenueDataPath, JSON.stringify(data, null, 2), 'utf-8');
}

function getEarningsData() {
  const data = readRevenueData();
  if (!data) {
    return null;
  }
  return {
    totalAnnualRevenue: data.totalRevenue,
    totalDailyRevenue: data.totalRevenue / 365,
    revenueStreams: {
      sampleRepo: {
        amount: data.totalRevenue,
        accountNumber: 'N/A',
      },
    },
    purchases: data.purchases
  };
}

app.get('/api/earnings', (req, res) => {
  const earnings = getEarningsData();
  if (!earnings) {
    return res.status(404).json({ error: 'Earnings data not found' });
  }
  res.json(earnings);
});

app.post('/api/purchase/home', (req, res) => {
  const data = readRevenueData();
  if (!data) {
    return res.status(404).json({ error: 'Revenue data not found' });
  }
  const cost = req.body.cost;
  if (typeof cost !== 'number' || cost <= 0) {
    return res.status(400).json({ error: 'Invalid cost value' });
  }
  if (data.totalRevenue < cost) {
    return res.status(400).json({ error: 'Insufficient revenue to make this purchase' });
  }
  data.totalRevenue -= cost;
  data.purchases.corporateHomes += cost;
  writeRevenueData(data);
  res.json({ message: 'Corporate home purchased successfully', remainingRevenue: data.totalRevenue, purchases: data.purchases });
});

app.post('/api/purchase/auto', (req, res) => {
  const data = readRevenueData();
  if (!data) {
    return res.status(404).json({ error: 'Revenue data not found' });
  }
  const { cost, model, vin, dealership } = req.body;
  if (typeof cost !== 'number' || cost <= 0) {
    return res.status(400).json({ error: 'Invalid cost value' });
  }
  if (!model || !vin || !dealership) {
    return res.status(400).json({ error: 'Missing required car details: model, vin, dealership' });
  }
  if (data.totalRevenue < cost) {
    return res.status(400).json({ error: 'Insufficient revenue to make this purchase' });
  }
  data.totalRevenue -= cost;
  data.purchases.autoFleet += cost;
  if (!data.purchases.autoFleetDetails) {
    data.purchases.autoFleetDetails = [];
  }
  data.purchases.autoFleetDetails.push({ model, vin, dealership, cost, purchaseDate: new Date().toISOString() });
  writeRevenueData(data);
  res.json({ message: 'Auto fleet purchased successfully', remainingRevenue: data.totalRevenue, purchases: data.purchases });
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
    '<div id="purchases"></div>',
    '<h2>Purchase Corporate Homes</h2>',
    '<input type="number" id="homeCost" placeholder="Enter cost" min="1" />',
    '<button onclick="purchaseHome()">Purchase Home</button>',
    '<h2>Purchase Auto Fleet</h2>',
  '<input type="number" id="autoCost" placeholder="Enter cost" min="1" />',
  '<input type="text" id="autoModel" placeholder="Enter car model" />',
  '<input type="text" id="autoVIN" placeholder="Enter VIN" />',
  '<input type="text" id="autoDealership" placeholder="Enter dealership" />',
  '<button onclick="purchaseAuto()">Purchase Auto Fleet</button>',
  '<script>',
  'async function fetchEarnings() {',
    '  const response = await fetch("/api/earnings", {',
    '    headers: { "Authorization": "Basic " + btoa("admin:securepassword") },',
    '    credentials: "include"',
    '  });',
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
    '  html += "<h3>Purchases:</h3>";',
    '  html += "<ul>";',
    '  html += "<li>Corporate Homes: $" + data.purchases.corporateHomes.toLocaleString() + "</li>";',
    '  html += "<li>Auto Fleet: $" + data.purchases.autoFleet.toLocaleString() + "</li>";',
    '  html += "</ul>";',
    '  document.getElementById("earnings").innerHTML = html;',
    '}',
    'async function purchaseHome() {',
    '  const cost = parseFloat(document.getElementById("homeCost").value);',
    '  if (isNaN(cost) || cost <= 0) {',
    '    alert("Please enter a valid cost for the home purchase.");',
    '    return;',
    '  }',
    '  const response = await fetch("/api/purchase/home", {',
    '    method: "POST",',
    '    headers: {',
    '      "Content-Type": "application/json",',
    '      "Authorization": "Basic " + btoa("admin:securepassword")',
    '    },',
    '    body: JSON.stringify({ cost })',
    '  });',
    '  const result = await response.json();',
    '  if (response.ok) {',
    '    alert(result.message);',
    '    fetchEarnings();',
    '  } else {',
    '    alert("Error: " + result.error);',
    '  }',
    '}',
  'async function purchaseAuto() {',
  '  const cost = parseFloat(document.getElementById("autoCost").value);',
  '  const model = document.getElementById("autoModel").value.trim();',
  '  const vin = document.getElementById("autoVIN").value.trim();',
  '  const dealership = document.getElementById("autoDealership").value.trim();',
  '  if (isNaN(cost) || cost <= 0) {',
  '    alert("Please enter a valid cost for the auto fleet purchase.");',
  '    return;',
  '  }',
  '  if (!model || !vin || !dealership) {',
  '    alert("Please enter all car details: model, VIN, and dealership.");',
  '    return;',
  '  }',
  '  const response = await fetch("/api/purchase/auto", {',
  '    method: "POST",',
  '    headers: {',
  '      "Content-Type": "application/json",',
  '      "Authorization": "Basic " + btoa("admin:securepassword")',
  '    },',
  '    body: JSON.stringify({ cost, model, vin, dealership })',
  '  });',
  '  const result = await response.json();',
  '  if (response.ok) {',
  '    alert(result.message);',
  '    fetchEarnings();',
  '  } else {',
  '    alert("Error: " + result.error);',
  '  }',
  '}',
  'fetchEarnings();',
  'async function fetchEarnings() {',
  '  const response = await fetch("/api/earnings", {',
  '    headers: { "Authorization": "Basic " + btoa("admin:securepassword") },',
  '    credentials: "include"',
  '  });',
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
  '  html += "<h3>Purchases:</h3>";',
  '  html += "<ul>";',
  '  html += "<li>Corporate Homes: $" + data.purchases.corporateHomes.toLocaleString() + "</li>";',
  '  html += "<li>Auto Fleet: $" + data.purchases.autoFleet.toLocaleString() + "</li>";',
  '  html += "</ul>";',
  '  if (data.purchases.autoFleetDetails && data.purchases.autoFleetDetails.length > 0) {',
  '    html += "<h3>Purchased Cars:</h3>";',
  '    html += "<ul>";',
  '    data.purchases.autoFleetDetails.forEach(car => {',
  '      html += `<li>Model: ${car.model}, VIN: ${car.vin}, Dealership: ${car.dealership}, Cost: $${car.cost.toLocaleString()}, Purchased on: ${new Date(car.purchaseDate).toLocaleDateString()}</li>`;',
  '    });',
  '    html += "</ul>";',
  '  }',
  '  document.getElementById("earnings").innerHTML = html;',
  '}',
    '</script>',
    '</body>',
    '</html>'
  ].join("");
  res.send(html);
});

const HOST = '0.0.0.0'; // Listen on all network interfaces

const server = app.listen(PORT, HOST, () => {
  console.log(`Earnings dashboard running at http://${HOST}:${PORT}`);
});

module.exports = { app, server };
