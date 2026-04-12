/**
 * Asset Service & Routes Tests
 * Tests CRUD operations for personal assets
 */

import mongoose from 'mongoose';
import supertest from 'supertest';
import PersonalAssetService from '../services/personalAssetService.js';
import Citizen from '../models/Citizen.js';
import Company from '../models/Company.js';
import app from '../server-enhanced.js'; // Adjust to your app export

const service = new PersonalAssetService();
const request = supertest(app);
let citizenId;
let citizen;
let assetId;

describe('PersonalAssetService', () => {
  beforeAll(async () => {
    await mongoose.connect('mongodb://localhost:27017/test');
  });

  afterAll(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.connection.close();
  });

  beforeEach(async () => {
    // Create test citizen
    citizen = await Citizen.create({
      citizenId: 'TEST-CITIZEN-001',
      personalInfo: {
        firstName: 'Test',
        lastName: 'Citizen',
        dateOfBirth: new Date('1990-01-01'),
        gender: 'other',
        nationalId: 'TEST123',
        biometricHash: 'testbiometric',
      },
      contactInfo: {
        phone: '1234567890',
        email: 'test@example.com',
        address: { city: 'Testville' },
      },
      bankingInfo: {
        accountNumber: '123456789',
        routingNumber: '111000614',
        bankName: 'Test Bank',
      },
    });
    citizenId = citizen.citizenId;
  });

  afterEach(async () => {
    await Citizen.deleteMany({});
    await Company.deleteMany({});
    // Clean other models...
  });

  test('getAllAssets returns empty for new citizen', async () => {
    const result = await service.getAllAssets(citizenId);
    expect(result.success).toBe(true);
    expect(result.assets.netWorth).toBe(0);
    expect(result.assets.companies).toEqual([]);
    expect(result.assets.assets).toEqual([]);
  });

  test('addAsset company and calculate netWorth', async () => {
    const assetData = {
      type: 'company',
      name: 'Test Corp',
      sharesOwned: 100,
      sharePrice: 10.5,
      totalValue: 1050,
    };

    const addResult = await service.addAsset(citizenId, assetData);
    expect(addResult.success).toBe(true);

    const getResult = await service.getAllAssets(citizenId);
    expect(getResult.success).toBe(true);
    expect(getResult.assets.netWorth).toBe(1050);
    expect(getResult.assets.assets.length).toBe(1);
    expect(getResult.assets.assets[0].value).toBe(1050);
    expect(citizen.assets[0].type).toBe('company');
  });

  test('updateAsset updates value and netWorth', async () => {
    // First add asset
    const addData = { type: 'stock', symbol: 'TEST', quantity: 50, pricePerShare: 20, totalValue: 1000 };
    const addResult = await service.addAsset(citizenId, addData);
    assetId = addResult.assetId;

    // Update
    const updateResult = await service.updateAsset(citizenId, assetId, { value: 2000 });
    expect(updateResult.success).toBe(true);

    // Verify netWorth updated
    const getResult = await service.getAllAssets(citizenId);
    expect(getResult.assets.netWorth).toBe(2000);
  });

  test('deleteAsset removes asset and updates netWorth', async () => {
    // Add asset
    const addData = { type: 'car', make: 'Test', model: 'ModelX', currentValue: 30000 };
    const addResult = await service.addAsset(citizenId, addData);
    assetId = addResult.assetId;

    // Delete
    const deleteResult = await service.deleteAsset(citizenId, assetId);
    expect(deleteResult.success).toBe(true);

    // Verify netWorth 0
    const getResult = await service.getAllAssets(citizenId);
    expect(getResult.assets.netWorth).toBe(0);
    expect(getResult.assets.assets.length).toBe(0);
  });

  test('netWorth virtual works on Citizen model', async () => {
    const citizenWithAssets = await Citizen.create({
      citizenId: 'NETWORTH-TEST',
      personalInfo: { firstName: 'Net', lastName: 'Worth', dateOfBirth: new Date(), gender: 'other', nationalId: 'NW1', biometricHash: 'hash' },
      contactInfo: { phone: '1', email: 'nw@test.com' },
      bankingInfo: { accountNumber: '1', routingNumber: '1', bankName: 'Test' },
      assets: [
        { type: 'company', refId: new mongoose.Types.ObjectId(), value: 10000 },
        { type: 'stock', refId: new mongoose.Types.ObjectId(), value: 5000 },
      ],
    });
    expect(citizenWithAssets.netWorth).toBe(15000);
  });
});

describe('Asset Routes', () => {
  test('GET /api/assets/:citizenId returns assets', async () => {
    const res = await request.get(`/api/assets/${citizenId}`).set('Authorization', 'Bearer validtoken'); // Assume mock auth
    expect(res.status).toBe(200);
    expect(res.body.netWorth).toBe(0);
  });

  test('POST /api/assets/:citizenId adds asset', async () => {
    const assetData = { type: 'patent', title: 'Test Patent', estimatedValue: 5000 };
    const res = await request
      .post(`/api/assets/${citizenId}`)
      .send(assetData)
      .set('Authorization', 'Bearer validtoken');
    expect(res.status).toBe(201);
    expect(res.body.assetId).toBeDefined();
  });
});

