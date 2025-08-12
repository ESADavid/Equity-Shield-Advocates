const request = require('supertest');
const app = require('../server-enhanced');

const authHeader = 'Basic ' + Buffer.from('admin:securepassword').toString('base64');

describe('Transaction Override API', () => {
  let createdOverrideId = null;

  test('GET /api/transactions/overrides - should return list of overrides', async () => {
    const res = await request(app)
      .get('/api/transactions/overrides')
      .set('Authorization', authHeader);
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('success', true);
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  test('POST /api/transactions/override - should create a new override request', async () => {
    const overrideData = {
      originalTransactionId: 'txn_12345',
      transactionType: 'purchase',
      overrideType: 'amount',
      originalValue: 100,
      newValue: 90,
      reason: 'Discount applied'
    };

    const res = await request(app)
      .post('/api/transactions/override')
      .set('Authorization', authHeader)
      .send(overrideData);

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('success', true);
    expect(res.body.data).toHaveProperty('id');
    createdOverrideId = res.body.data.id;
  });

  test('PUT /api/transactions/:id/override - should update an existing override', async () => {
    if (!createdOverrideId) {
      return;
    }
    const res = await request(app)
      .put(`/api/transactions/${createdOverrideId}/override`)
      .set('Authorization', authHeader)
      .send({ newValue: 85, reason: 'Further discount' });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('success', true);
  });

  test('GET /api/transactions/:id/audit - should get audit trail', async () => {
    const res = await request(app)
      .get('/api/transactions/txn_12345/audit')
      .set('Authorization', authHeader);

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('success', true);
    expect(res.body.data).toHaveProperty('auditTrail');
    expect(Array.isArray(res.body.data.auditTrail)).toBe(true);
  });

  test('DELETE /api/transactions/:id/override - should reject override request', async () => {
    if (!createdOverrideId) {
      return;
    }
    const res = await request(app)
      .delete(`/api/transactions/${createdOverrideId}/override`)
      .set('Authorization', authHeader)
      .send({ reason: 'Invalid request' });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('success', true);
  });
});
