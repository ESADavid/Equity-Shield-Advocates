const request = require('supertest');
const { app, server } = require('./server'); // Adjust the path if necessary

afterAll(() => {
  server.close();
});

describe('Earnings Dashboard API Tests', () => {
  describe('GET /api/earnings', () => {
    it('should return earnings data with status 200', async () => {
      const response = await request(app)
        .get('/api/earnings')
        .auth('admin', 'securepassword');
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('totalAnnualRevenue');
      expect(response.body).toHaveProperty('totalDailyRevenue');
      expect(response.body).toHaveProperty('revenueStreams');
    });

    it('should return 401 if authentication fails', async () => {
      const response = await request(app)
        .get('/api/earnings')
        .auth('wronguser', 'wrongpassword');
      expect(response.status).toBe(401);
    });
  });

  describe('GET /api/earnings/download', () => {
    it('should return a JSON file with earnings data', async () => {
      const response = await request(app)
        .get('/api/earnings/download')
        .auth('admin', 'securepassword');
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('application/json');
      expect(response.headers['content-disposition']).toContain('attachment; filename="earnings_report.json"');
    });

    it('should return 401 if authentication fails', async () => {
      const response = await request(app)
        .get('/api/earnings/download')
        .auth('wronguser', 'wrongpassword');
      expect(response.status).toBe(401);
    });
  });

  describe('GET /', () => {
    it('should return the HTML dashboard', async () => {
      const response = await request(app)
        .get('/')
        .auth('admin', 'securepassword');
      expect(response.status).toBe(200);
      expect(response.text).toContain('<h1>OWLban Earnings Dashboard</h1>');
    });

    it('should return 401 if authentication fails', async () => {
      const response = await request(app)
        .get('/')
        .auth('wronguser', 'wrongpassword');
      expect(response.status).toBe(401);
    });
  });

  describe('Error Handling', () => {
    it('should return 500 for an internal server error', async () => {
      const originalGetRevenueReport = require('../FOUR-ERA-AI/src/wealth-creation-engine-new').default.prototype.getRevenueReport;
      const wealthEngineInstance = require('../FOUR-ERA-AI/src/wealth-creation-engine-new').default.prototype;
      const originalMethod = wealthEngineInstance.getRevenueReport;
      wealthEngineInstance.getRevenueReport = () => { throw new Error('Test error'); };

      const response = await request(app)
        .get('/api/earnings')
        .auth('admin', 'securepassword');

      wealthEngineInstance.getRevenueReport = originalMethod;

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('error', 'Failed to fetch earnings data');
    });
  });

  describe('Invalid Routes', () => {
    it('should return 404 for unknown route', async () => {
      const response = await request(app)
        .get('/invalid-route')
        .auth('admin', 'securepassword');
      expect(response.status).toBe(404);
    });
  });

  describe('Unsupported Methods on /api/earnings', () => {
    it('should return 404 or 405 for POST method', async () => {
      const response = await request(app)
        .post('/api/earnings')
        .auth('admin', 'securepassword');
      expect([404, 405]).toContain(response.status);
    });
  });

  describe('Malformed Requests', () => {
    it('should return 401 if Authorization header is missing', async () => {
      const response = await request(app)
        .get('/api/earnings');
      expect(response.status).toBe(401);
    });
  });
});
