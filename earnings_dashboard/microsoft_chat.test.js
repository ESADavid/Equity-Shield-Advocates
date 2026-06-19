import request from 'supertest';
import { app } from './server.js';

describe('GET /microsoft/chat', () => {
  it('should return 200 and success message with valid query parameters', async () => {
    const response = await request(app)
      .get('/microsoft/chat')
      .auth('BSEAN4890@GMAIL.COM', 'TBROOME704')
      .query({
        auth: '2',
        origin: 'ProfileAboutMe',
        origindomain: 'microsoft365',
        redirectOrgId: 'dc3405c4-651b-4650-8231-78739bd4f8c6',
        redirectUserId: 'user123',
      });
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty(
      'message',
      'Microsoft chat/profile auth redirect received'
    );
    expect(response.body).toHaveProperty('query');
    expect(response.body.query).toMatchObject({
      auth: '2',
      origin: 'ProfileAboutMe',
      origindomain: 'microsoft365',
      redirectOrgId: 'dc3405c4-651b-4650-8231-78739bd4f8c6',
      redirectUserId: 'user123',
    });
  });

  it('should return 400 error if required query parameters are missing', async () => {
    const response = await request(app)
      .get('/microsoft/chat')
      .auth('BSEAN4890@GMAIL.COM', 'TBROOME704')
      .query({
        auth: '2',
        origin: 'ProfileAboutMe',
      });
    expect(response.statusCode).toBe(400);
    expect(response.body).toHaveProperty('error');
  });

  it('should handle unexpected errors gracefully', async () => {
    const response = await request(app)
      .get('/microsoft/chat')
      .auth('BSEAN4890@GMAIL.COM', 'TBROOME704')
      .query(null);
    expect([400, 500]).toContain(response.statusCode);
  });
});
