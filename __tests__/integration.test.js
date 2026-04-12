import request from 'supertest';
import { app } from '../server-enhanced.js'; // Assume app export



describe('Phase 3 Integration Tests - E2E Flows', () => {
  test('E2E flow: register citizen → UBI payment → partner onboard', async () => {
    // 1. Register citizen
    const citizenRes = await request(app)
      .post('/api/citizen-portal/register')
      .send({ name: 'John Doe', ssn: '123-45-6789', address: '123 Main St' });
    expect(citizenRes.status).toBe(201);
    expect(citizenRes.body.success).toBe(true);

    // 2. Process UBI (assume auth for simplicity, mock if needed)
    const ubiRes = await request(app)
      .post('/api/citizen-portal/ubi-payment')
      .send({ citizenId: citizenRes.body.citizenId, amount: 1000, month: '2024-01' });
    expect(ubiRes.status).toBe(200);

    // 3. Onboard partner
    const partnerRes = await request(app)
      .post('/api/partners/onboard')
      .send({ companyName: 'Academi', email: 'partner@academi.com' });
    expect(partnerRes.status).toBe(201);
  });
});
