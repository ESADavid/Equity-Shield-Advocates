function handleIncome(data) {
  if (data.amount <= 0) return 0;

  if (data.currency === 'USD') {
    if (data.source === 'salary') {
      return data.amount * 1.1;
    } else if (data.source === 'investment') {
      return data.amount * 1.2;
    } else {
      return data.amount;
    }
  } else if (data.currency === 'EUR') {
    if (data.source === 'salary') {
      return data.amount * 1.05;
    } else if (data.source === 'investment') {
      return data.amount * 1.15;
    } else {
      return data.amount * 0.9;
    }
  } else {
    return data.amount;
  }
}

function handleExpense(data) {
  if (data.amount <= 0) return 0;

  if (data.currency === 'USD') {
    if (data.category === 'food') {
      return -data.amount;
    } else if (data.category === 'transport') {
      return -data.amount * 1.1;
    } else {
      return -data.amount;
    }
  } else if (data.currency === 'EUR') {
    if (data.category === 'food') {
      return -data.amount * 0.9;
    } else if (data.category === 'transport') {
      return -data.amount * 1.05;
    } else {
      return -data.amount;
    }
  } else {
    return -data.amount;
  }
}

function processRevenue(data) {
  if (data.type === 'income') {
    return handleIncome(data);
  } else if (data.type === 'expense') {
    return handleExpense(data);
  } else {
    return 0;
  }
}

module.exports = { processRevenue };
