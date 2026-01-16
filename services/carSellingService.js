const Car = require('../models/Car.js');
const { info, error } = require('../utils/loggerWrapper.js');

class CarSellingService {
  constructor() {
    this.inventory = new Map();
    this.sales = new Map();
  }

  async addCar(carData, userId, tenantId) {
    try {
      const car = new Car({
        ...carData,
        tenantId,
        createdBy: userId,
        carId: `CAR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
      });

      await car.save();

      this.inventory.set(car.carId, car);
      info(`Car added to inventory: ${car.make} ${car.model} (${car.year}) - $${car.askingPrice}`, {
        service: 'car-selling',
        carId: car.carId,
        userId,
        tenantId
      });

      return {
        success: true,
        car: car,
        message: `Car added to inventory successfully. Asking price: $${car.askingPrice}`
      };
    } catch (err) {
      error('Error adding car to inventory:', err.message, {
        service: 'car-selling',
        userId,
        tenantId
      });
      throw new Error(`Failed to add car: ${err.message}`);
    }
  }

  async sellCar(carId, sellingPrice, buyerInfo, soldBy, tenantId) {
    try {
      const car = await Car.findOne({ carId, tenantId });

      if (!car) {
        throw new Error('Car not found in inventory');
      }

      if (car.status !== 'available') {
        throw new Error('Car is not available for sale');
      }

      // Update car status
      car.status = 'sold';
      car.soldPrice = sellingPrice;
      car.soldBy = soldBy;
      car.soldAt = new Date();

      await car.save();

      // Calculate profit
      const profit = car.profitLoss;
      const profitPercent = car.profitLossPercent;

      // Record sale
      const saleRecord = {
        carId: car.carId,
        make: car.make,
        model: car.model,
        year: car.year,
        purchasePrice: car.purchasePrice,
        sellingPrice: sellingPrice,
        profit: profit,
        profitPercent: profitPercent,
        soldAt: car.soldAt,
        soldBy: soldBy,
        buyerInfo: buyerInfo,
        daysOnMarket: car.daysOnMarket
      };

      this.sales.set(carId, saleRecord);

      info(`Car sold: ${car.make} ${car.model} (${car.year}) - Sold for $${sellingPrice}, Profit: $${profit} (${profitPercent.toFixed(2)}%)`, {
        service: 'car-selling',
        carId,
        soldBy,
        tenantId
      });

      return {
        success: true,
        sale: saleRecord,
        message: `Car sold successfully for $${sellingPrice}. Profit: $${profit} (${profitPercent.toFixed(2)}%)`
      };
    } catch (err) {
      error('Error selling car:', err.message, {
        service: 'car-selling',
        carId,
        soldBy,
        tenantId
      });
      throw new Error(`Failed to sell car: ${err.message}`);
    }
  }

  async getInventory(tenantId) {
    try {
      const cars = await Car.find({ tenantId, status: 'available' }).sort({ createdAt: -1 });
      return {
        success: true,
        inventory: cars,
        totalValue: cars.reduce((sum, car) => sum + car.currentValue, 0),
        count: cars.length
      };
    } catch (err) {
      error('Error getting inventory:', err.message, {
        service: 'car-selling',
        tenantId
      });
      throw new Error(`Failed to get inventory: ${err.message}`);
    }
  }

  async getSalesReport(tenantId, startDate, endDate) {
    try {
      const query = { tenantId, status: 'sold' };

      if (startDate && endDate) {
        query.soldAt = { $gte: new Date(startDate), $lte: new Date(endDate) };
      }

      const soldCars = await Car.find(query).sort({ soldAt: -1 });

      const totalRevenue = soldCars.reduce((sum, car) => sum + (car.soldPrice || 0), 0);
      const totalProfit = soldCars.reduce((sum, car) => sum + car.profitLoss, 0);
      const averageProfitPercent = soldCars.length > 0 ?
        soldCars.reduce((sum, car) => sum + car.profitLossPercent, 0) / soldCars.length : 0;

      return {
        success: true,
        sales: soldCars,
        summary: {
          totalSales: soldCars.length,
          totalRevenue: totalRevenue,
          totalProfit: totalProfit,
          averageProfitPercent: averageProfitPercent,
          period: startDate && endDate ? `${startDate} to ${endDate}` : 'All time'
        }
      };
    } catch (err) {
      error('Error getting sales report:', err.message, {
        service: 'car-selling',
        tenantId
      });
      throw new Error(`Failed to get sales report: ${err.message}`);
    }
  }

  async updateCarValue(carId, newValue, updatedBy, tenantId) {
    try {
      const car = await Car.findOne({ carId, tenantId });

      if (!car) {
        throw new Error('Car not found');
      }

      car.currentValue = newValue;
      await car.save();

      info(`Car value updated: ${car.make} ${car.model} - New value: $${newValue}`, {
        service: 'car-selling',
        carId,
        updatedBy,
        tenantId
      });

      return {
        success: true,
        car: car,
        message: `Car value updated to $${newValue}`
      };
    } catch (err) {
      error('Error updating car value:', err.message, {
        service: 'car-selling',
        carId,
        updatedBy,
        tenantId
      });
      throw new Error(`Failed to update car value: ${err.message}`);
    }
  }

  // Quick sell method for immediate revenue generation
  async quickSell(carId, discountPercent = 10, soldBy, tenantId) {
    try {
      const car = await Car.findOne({ carId, tenantId });

      if (!car) {
        throw new Error('Car not found');
      }

      if (car.status !== 'available') {
        throw new Error('Car is not available for sale');
      }

      const sellingPrice = car.askingPrice * (1 - discountPercent / 100);

      return await this.sellCar(carId, sellingPrice, { type: 'quick_sale' }, soldBy, tenantId);
    } catch (err) {
      error('Error quick selling car:', err.message, {
        service: 'car-selling',
        carId,
        soldBy,
        tenantId
      });
      throw new Error(`Failed to quick sell car: ${err.message}`);
    }
  }

  // Bulk operations for rapid revenue generation
  async bulkQuickSell(carIds, discountPercent = 15, soldBy, tenantId) {
    const results = [];
    let totalRevenue = 0;

    for (const carId of carIds) {
      try {
        const result = await this.quickSell(carId, discountPercent, soldBy, tenantId);
        results.push(result);
        totalRevenue += result.sale.sellingPrice;
      } catch (err) {
        results.push({
          success: false,
          carId,
          error: err.message
        });
      }
    }

    return {
      success: true,
      results,
      summary: {
        totalCarsProcessed: carIds.length,
        successfulSales: results.filter(r => r.success).length,
        totalRevenue: totalRevenue,
        averageDiscount: discountPercent
      }
    };
  }
}

module.exports = CarSellingService;
