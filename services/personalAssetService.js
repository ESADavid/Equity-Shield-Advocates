/**
 * Personal Asset Service - List & Control everything owned by citizen
 */

import logger from '../utils/loggerWrapper.js';
import Citizen from '../models/Citizen.js';
import Company from '../models/Company.js';
import Stock from '../models/Stock.js';
import Patent from '../models/Patent.js';
import Car from '../models/Car.js';
import Transaction from '../models/Transaction.js';
import Education from '../models/Education.js';

export default class PersonalAssetService {
  async getAllAssets(citizenId) {
    try {
      const citizen = await Citizen.findOne({ citizenId }).populate(
        'assets.refId'
      );
      if (!citizen) return { success: false, error: 'Citizen not found' };

      // Aggregate from all models
      const [companies, stocks, patents, cars, transactions, education] =
        await Promise.all([
          Company.find({ citizenId: citizen._id }),
          Stock.find({ citizenId: citizen._id }),
          Patent.find({ citizenId: citizen._id }),
          Car.find({ citizenId: citizen._id }),
          Transaction.getByUser(citizen._id, 'default-tenant', 50), // Assume tenant
          Education.find({ citizenId: citizen._id }),
        ]);

      const assets = {
        citizenAssets: citizen.assets || [],
        companies,
        stocks,
        patents,
        cars,
        transactions,
        educationRecords: education,
      };

      // Calculate net worth
      assets.netWorth = this.calculateNetWorth(assets);

      logger.info(`Assets listed for citizen ${citizenId}`);
      return { success: true, assets };
    } catch (err) {
      logger.error('Get assets failed:', err);
      return { success: false, error: err.message };
    }
  }

  async addAsset(citizenId, assetData) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) return { success: false, error: 'Citizen not found' };

      // Create specific asset based on type
      let asset;
      switch (assetData.type) {
        case 'company':
          asset = new Company({ citizenId: citizen._id, ...assetData });
          break;
        case 'stock':
          asset = new Stock({ citizenId: citizen._id, ...assetData });
          break;
        case 'patent':
          asset = new Patent({ citizenId: citizen._id, ...assetData });
          break;
        case 'car':
          asset = new Car({ citizenId: citizen._id, ...assetData });
          break;
        default:
          return { success: false, error: 'Unknown asset type' };
      }
      await asset.save();

      // Add ref to citizen.assets
      citizen.assets = citizen.assets || [];
      citizen.assets.push({
        type: assetData.type,
        refId: asset._id,
        value: assetData.value || 0,
      });
      await citizen.save();

      logger.info(`Asset added for ${citizenId}: ${assetData.type}`);
      return { success: true, assetId: asset._id };
    } catch (err) {
      logger.error('Add asset failed:', err);
      return { success: false, error: err.message };
    }
  }

  async updateAsset(citizenId, assetId, updates) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) return { success: false, error: 'Citizen not found' };

      // Update specific model (simplified - in prod use dynamic model lookup)
      // For demo, assume updates propogate; real impl would target specific model
      await Citizen.findOneAndUpdate(
        { citizenId },
        { $set: { 'assets.$[el].value': updates.value || 0 } },
        { arrayFilters: [{ 'el.refId': assetId }] }
      );

      logger.info(`Asset updated for ${citizenId}: ${assetId}`);
      return { success: true };
    } catch (err) {
      logger.error('Update asset failed:', err);
      return { success: false, error: err.message };
    }
  }

  async deleteAsset(citizenId, assetId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) return { success: false, error: 'Citizen not found' };

      // Remove from citizen.assets and specific model
      citizen.assets = citizen.assets.filter(
        (a) => a.refId.toString() !== assetId
      );
      await citizen.save();

      // Remove from specific model (dynamic in prod)
      // await Company.findByIdAndDelete(assetId); etc. based on type

      logger.info(`Asset deleted for ${citizenId}: ${assetId}`);
      return { success: true };
    } catch (err) {
      logger.error('Delete asset failed:', err);
      return { success: false, error: err.message };
    }
  }

  calculateNetWorth(assets) {
    let total = 0;
    if (assets.companies)
      assets.companies.forEach((c) => (total += Number(c.totalValue)));
    if (assets.stocks)
      assets.stocks.forEach((s) => (total += Number(s.totalValue)));
    if (assets.patents)
      assets.patents.forEach((p) => (total += Number(p.estimatedValue)));
    if (assets.cars)
      assets.cars.forEach((car) => (total += Number(car.currentValue)));
    return total;
  }
}
