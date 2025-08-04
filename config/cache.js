// config/cache.js (New file)
const redis = require('redis');
const logger = require('../utils/logger'); // adjust path if needed


let client;

const initializeRedis = async () => {
  client = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  });

  client.on('error', (err) => logger.error('Redis error:', err));
  await client.connect();
  logger.info('✅ Redis initialized successfully');
};

const getCached = async (key) => {
  const data = await client.get(key);
  return data ? JSON.parse(data) : null;
};

const setCached = async (key, value, expiry = 3600) => {
  await client.setEx(key, expiry, JSON.stringify(value));
};

module.exports = { initializeRedis, getCached, setCached };