const request = require('supertest');
const { app } = require('./server');

describe('Authentication and Access Control Tests', () => {
  const adminUser = process.env.ADMIN_USER || 'admin';
  const adminPass = process.env.ADMIN_PASS || 'securepassword';

  test('Rejects requests without basic auth', async () => {
    const res = await request(app).get('/api/earnings');
    expect(res.statusCode).toBe(401);
  });

  test('Rejects requests with wrong basic auth', async () => {
    const res = await request(app)
      .get('/api/earnings')
      .auth('wronguser', 'wrongpass');
    expect(res.statusCode).toBe(401);
  });

  test('Allows requests with correct basic auth', async () => {
    const res = await request(app)
      .get('/api/earnings')
      .auth(adminUser, adminPass);
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('totalAnnualRevenue');
  });

  test('Allows masterLoginOverride with special header', async () => {
    const res = await request(app)
      .get('/api/earnings')
      .set('x-override-user', 'Oscar Broome');
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('totalAnnualRevenue');
  });

  test('Allows masterLoginOverride with query param', async () => {
    const res = await request(app)
      .get('/api/earnings?overrideUser=Oscar Broome');
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('totalAnnualRevenue');
  });
});
