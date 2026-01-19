import { info, error, warn, debug } from './utils/loggerWrapper.js';

document.addEventListener('DOMContentLoaded', () => {
  const spendSection = document.querySelector('.spend-section');
  const summarySection = document.querySelector('.summary-section');
  const fleetSection = document.querySelector('.fleet-section');
  const currentBalanceEl = document.getElementById('current-balance');
  const transactionList = document.getElementById('transaction-list');
  const carListEl = document.getElementById('car-list');
  const purchasedCarListEl = document.getElementById('purchased-car-list');

  const authHeader = 'Basic ' + btoa('admin:securepassword');

  let balance = 0;
  let transactions = [];
  let purchasedCars = [];
  let cars = []; // Will be fetched from backend purchases or API

  async function fetchEarningsFromBackend() {
    try {
      info('Fetching earnings from backend...');
      const response = await fetch('/api/earnings', {
        headers: { Authorization: authHeader },
      credentials: 'include',
      });
      info('Fetch response status:', response.status);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      info('Earnings data received:', data);
      balance = data.totalAnnualRevenue;
      transactions = []; // Backend does not provide generic transactions, so keep empty or could be enhanced
      purchasedCars = data.purchases.autoFleetDetails || [];
      renderBalance();
      renderPurchasedCars();
      spendSection.style.display = 'block';
      summarySection.style.display = 'block';
      fleetSection.style.display = 'block';
    } catch (error) {
      error('Failed to fetch earnings from backend:', error);
      alert('Failed to load earnings data. Please try again later.');
    }
  }

  function renderBalance() {
    currentBalanceEl.textContent = balance.toFixed(2);
  }

  function renderTransactions() {
    transactionList.innerHTML = '';
    transactions.forEach((t, index) => {
      const li = document.createElement('li');
      li.textContent = `${t.description} - $${t.amount.toFixed(2)} [${t.category}]`;

      const deleteBtn = document.createElement('button');
      deleteBtn.textContent = 'Delete';
      deleteBtn.style.marginLeft = '1rem';
      deleteBtn.addEventListener('click', () => {
        transactions.splice(index, 1);
        updateBalance();
        renderTransactions();
      });

      li.appendChild(deleteBtn);
      transactionList.appendChild(li);
    });
  }

  async function fetchCarsFromBackend() {
    // For now, use purchasedCars as cars available for purchase is not provided by backend
    // Alternatively, could fetch from external API or backend endpoint if available
    // Here, we simulate cars available for purchase by filtering out purchased cars from a static list or empty list
    // For demo, we use a static list of cars
    cars = [
      { model: 'Tesla Model S', price: 79999 },
      { model: 'BMW X5', price: 60999 },
      { model: 'Audi Q7', price: 54999 },
    ];
    // Remove cars already purchased by VIN or model if VIN not available
    const purchasedModels = new Set(purchasedCars.map((car) => car.model));
    cars = cars.filter((car) => !purchasedModels.has(car.model));
    renderCarList();
  }

  function updateBalance() {
    // Balance is managed by backend, so here just re-render
    renderBalance();
  }

  function renderCarList() {
    carListEl.innerHTML = '';
    cars.forEach((car) => {
      const li = document.createElement('li');
      li.textContent = `${car.model} - $${car.price.toFixed(2)}`;

      const purchaseBtn = document.createElement('button');
      purchaseBtn.textContent = 'Purchase';
      purchaseBtn.style.marginLeft = '1rem';
      purchaseBtn.addEventListener('click', async () => {
        if (car.price > balance) {
          alert('Insufficient balance to purchase this car.');
          return;
        }
        // Call backend API to purchase auto fleet
        const vin = 'VIN-' + Math.floor(Math.random() * 1000000); // Generate dummy VIN
        const dealership = 'Default Dealership'; // Placeholder
        try {
          const response = await fetch('/api/purchase/auto', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: authHeader,
            },
            body: JSON.stringify({
              cost: car.price,
              model: car.model,
              vin,
              dealership,
            }),
          });
          const result = await response.json();
          if (response.ok) {
            alert(result.message);
            balance = result.remainingRevenue;
            purchasedCars.push({
              model: car.model,
              vin,
              dealership,
              cost: car.price,
              purchaseDate: new Date().toISOString(),
              deliveryStatus: 'pending',
              deliveryDate: null,
              deliveryAddress: null,
            });
            cars = cars.filter((c) => c.model !== car.model);
            renderBalance();
            renderCarList();
            renderPurchasedCars();
          } else {
            alert('Error: ' + result.error);
          }
        } catch (error) {
          alert('Failed to make purchase: ' + error.message);
        }
      });

      li.appendChild(purchaseBtn);
      carListEl.appendChild(li);
    });
  }

  function renderPurchasedCars() {
    purchasedCarListEl.innerHTML = '';
    purchasedCars.forEach((car) => {
      const li = document.createElement('li');
      li.textContent = `${car.model} - $${car.cost.toFixed(2)} (VIN: ${car.vin})`;
      purchasedCarListEl.appendChild(li);
    });
  }

  // Remove local spend form and transactions as backend does not support generic spending transactions
  // Optionally, could implement backend API for generic spending if needed

  // Initialize UI by fetching earnings and cars from backend
  fetchEarningsFromBackend().then(() => {
    fetchCarsFromBackend();
  });
});
