document.addEventListener('DOMContentLoaded', () => {
  const initialMoneyInput = document.getElementById('initial-money');
  const setMoneyBtn = document.getElementById('set-money-btn');
  const spendSection = document.querySelector('.spend-section');
  const summarySection = document.querySelector('.summary-section');
  const fleetSection = document.querySelector('.fleet-section');
  const currentBalanceEl = document.getElementById('current-balance');
  const transactionList = document.getElementById('transaction-list');
  const spendForm = document.getElementById('spend-form');
  const carListEl = document.getElementById('car-list');
  const purchasedCarListEl = document.getElementById('purchased-car-list');


  let balance = 0;
  let transactions = [];
  let purchasedCars = [];

  let cars = []; // Will be fetched from API

  async function fetchCarsFromAPI() {
    try {
      const response = await fetch('https://api.example.com/cars');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      cars = data.cars || [];
      renderCarList();
    } catch (error) {
      console.error('Failed to fetch cars from API:', error);
      alert('Failed to load car data. Please try again later.');
    }
  }

  function updateBalance() {
    const totalSpent = transactions.reduce((sum, t) => sum + t.amount, 0);
    balance = initialMoneyInput.value - totalSpent;
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

  function renderCarList() {
    carListEl.innerHTML = '';
    cars.forEach((car, index) => {
      const li = document.createElement('li');
      li.textContent = `${car.model} - $${car.price.toFixed(2)}`;

      const purchaseBtn = document.createElement('button');
      purchaseBtn.textContent = 'Purchase';
      purchaseBtn.style.marginLeft = '1rem';
      purchaseBtn.addEventListener('click', () => {
        if (car.price > balance) {
          alert('Insufficient balance to purchase this car.');
          return;
        }
        // Add purchase as a transaction
        transactions.push({
          amount: car.price,
          description: `Purchased ${car.model}`,
          category: 'Corporate Fleet',
        });
        purchasedCars.push(car);
        updateBalance();
        renderTransactions();
        renderPurchasedCars();
      });

      li.appendChild(purchaseBtn);
      carListEl.appendChild(li);
    });
  }

  function renderPurchasedCars() {
    purchasedCarListEl.innerHTML = '';
    purchasedCars.forEach((car) => {
      const li = document.createElement('li');
      li.textContent = `${car.model} - $${car.price.toFixed(2)}`;
      purchasedCarListEl.appendChild(li);
    });
  }

  setMoneyBtn.addEventListener('click', () => {
    const value = parseFloat(initialMoneyInput.value);
    if (isNaN(value) || value < 0) {
      alert('Please enter a valid non-negative number for your available money.');
      return;
    }
    balance = value;
    spendSection.style.display = 'block';
    summarySection.style.display = 'block';
    fleetSection.style.display = 'block';
    updateBalance();
    fetchCarsFromAPI();
    renderPurchasedCars();
  });

  const purchaseAllBtn = document.getElementById('purchase-all-btn');
  purchaseAllBtn.addEventListener('click', () => {
    const totalPrice = cars.reduce((sum, car) => sum + car.price, 0);
    if (totalPrice > balance) {
      alert('Insufficient balance to purchase all cars.');
      return;
    }
    cars.forEach((car) => {
      transactions.push({
        amount: car.price,
        description: `Purchased ${car.model}`,
        category: 'Corporate Fleet',
      });
      purchasedCars.push(car);
    });
    updateBalance();
    renderTransactions();
    renderPurchasedCars();
  });

  spendForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const amount = parseFloat(document.getElementById('spend-amount').value);
    const description = document.getElementById('spend-description').value.trim();
    const category = document.getElementById('spend-category').value;

    if (isNaN(amount) || amount <= 0) {
      alert('Please enter a valid amount greater than zero.');
      return;
    }
    if (!description) {
      alert('Please enter a description.');
      return;
    }
    if (!category) {
      alert('Please select a category.');
      return;
    }
    if (amount > balance) {
      alert('Insufficient balance for this transaction.');
      return;
    }

    transactions.push({ amount, description, category });
    updateBalance();
    renderTransactions();

    spendForm.reset();
  });
});
