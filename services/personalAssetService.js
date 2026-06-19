/**
 * Personal Asset Service
 * OSCAR-BROOME-REVENUE System - Proprietary Technology
 * 
 * © 2024 OWLBAN GROUP 🦉 - All Rights Reserved
 * Owned by: King Sachem Yochanan (Oscar Broome)
 * Authority: House of David ✡️, House of Capet ⚜️, House of Logan 🏰
 * 
 * PROTECTED BY CUSTOM ENCRYPTION - DO NOT SHARE
 * This module implements proprietary encryption methods.
 * Access and use subject to OWLBAN GROUP ownership and licensing.
 */

import logger from '../utils/loggerWrapper.js';
import Citizen from '../models/Citizen.js';
import Company from '../models/Company.js';
import Stock from '../models/Stock.js';
import Patent from '../models/Patent.js';
import Car from '../models/Car.js';
import Transaction from '../models/Transaction.js';
import Education from '../models/Education.js';

/**
 * @typedef {Object} AssetData
 * @property {string} type
 * @property {number} [value]
 */

/**
 * @typedef {Object} UpdateData
 * @property {number} [value]
 */

/**
 * @typedef {Object} AssetItem
 * @property {string} type
 * @property {any} refId
 * @property {number} value
 */

/**
 * @typedef {Object} AssetCollection
 * @property {AssetItem[]} [citizenAssets]
 * @property {any[]} [companies]
 * @property {any[]} [stocks]
 * @property {any[]} [patents]
 * @property {any[]} [cars]
 * @property {any[]} [transactions]
 * @property {any[]} [educationRecords]
 * @property {number} [netWorth]
 */

export default class PersonalAssetService {
  /**
   * Get all assets for a citizen
   * @param {string} citizenId - The citizen ID
   * @returns {Promise<any>}
   */
  async getAllAssets(citizenId) {
    try {
      const citizen = await Citizen.findOne({ citizenId }).populate(
        'assets.refId'
      );
      if (!citizen) return { success: false, error: 'Citizen not found' };

// Aggregate from all models
      // Note: Transaction.getByUser(userId, tenantId, limit) - order is userId, tenantId, limit
      // Using type assertion to call the static method
      const [companies, stocks, patents, cars, transactions, education] =
        await Promise.all([
          Company.find({ citizenId: citizen._id }),
          Stock.find({ citizenId: citizen._id }),
          Patent.find({ citizenId: citizen._id }),
          Car.find({ citizenId: citizen._id }),
          /** @type {any} */ (Transaction).getByUser(citizen._id, 'default-tenant', 50),
          Education.find({ citizenId: citizen._id }),
        ]);

      /** @type {AssetCollection} */
      const assets = {
        /** @type {any} */
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

  /**
   * Add a new asset for a citizen
   * @param {string} citizenId - The citizen ID
   * @param {AssetData} assetData - The asset data
   * @returns {Promise<any>}
   */
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

/**
   * Update an existing asset
   * @param {string} citizenId - The citizen ID
   * @param {string} assetId - The asset ID
   * @param {UpdateData} updates - The update data
   * @returns {Promise<any>}
   */
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

  /**
   * Delete an asset
   * @param {string} citizenId - The citizen ID
   * @param {string} assetId - The asset ID
   * @returns {Promise<any>}
   */
  async deleteAsset(citizenId, assetId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) return { success: false, error: 'Citizen not found' };

// Remove from citizen.assets and specific model
      /** @type {any[]} */
      const assetList = citizen.assets || [];
      citizen.assets = assetList.filter(
        /** @type {(a: any) => boolean} */ ((a) => a.refId.toString() !== assetId)
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

  /**
   * Calculate the net worth from assets
   * @param {AssetCollection} assets - The asset collection
   * @returns {number}
   */
  calculateNetWorth(assets) {
    let total = 0;
    if (assets.companies)
      /** @type {any[]} */
      (assets.companies).forEach((c) => (total += Number(c.totalValue)));
    if (assets.stocks)
      /** @type {any[]} */
      (assets.stocks).forEach((s) => (total += Number(s.totalValue)));
    if (assets.patents)
      /** @type {any[]} */
      (assets.patents).forEach((p) => (total += Number(p.estimatedValue)));
    if (assets.cars)
      /** @type {any[]} */
      (assets.cars).forEach((car) => (total += Number(car.currentValue)));
    return total;
  }
}
