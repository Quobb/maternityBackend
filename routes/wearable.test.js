// routes/wearable.test.js (Example)
const request = require('supertest');
const app = require('../server');
const { getSupabaseClient } = require('../config/database');

jest.mock('../config/database');
jest.mock('axios');

describe('POST /api/wearable/assess-risk', () => {
  it('should return risk assessment', async () => {
    getSupabaseClient.mockReturnValue({
      from: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      single: jest.fn().mockResolvedValue({ data: { start_date: '2025-01-01' } }),
    });

    const response = await request(app)
      .post('/api/wearable/assess-risk')
      .set('Authorization', 'Bearer valid-token')
      .expect(200);

    expect(response.body.riskAssessment).toHaveProperty('risk_level');
  });
});