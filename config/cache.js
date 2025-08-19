// config/cache.js - In-memory cache (no Redis)
const logger = require('../utils/logger');

// In-memory cache store
const cache = new Map();
const cacheExpiry = new Map();

// Clean up expired entries periodically
const cleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, expireTime] of cacheExpiry.entries()) {
    if (now > expireTime) {
      cache.delete(key);
      cacheExpiry.delete(key);
    }
  }
}, 60000); // Clean up every minute

const getCached = async (key) => {
  try {
    // Check if key has expired
    const expireTime = cacheExpiry.get(key);
    if (expireTime && Date.now() > expireTime) {
      cache.delete(key);
      cacheExpiry.delete(key);
      return null;
    }
    
    const data = cache.get(key);
    return data || null;
  } catch (error) {
    logger.error('Cache get error for key', key, ':', error.message);
    return null;
  }
};

const setCached = async (key, value, ttlSeconds = 3600) => {
  try {
    cache.set(key, value);
    
    // Set expiry time
    if (ttlSeconds > 0) {
      const expireTime = Date.now() + (ttlSeconds * 1000);
      cacheExpiry.set(key, expireTime);
    }
    
    return true;
  } catch (error) {
    logger.error('Cache set error for key', key, ':', error.message);
    return false;
  }
};

const deleteCached = async (key) => {
  try {
    const deleted = cache.delete(key);
    cacheExpiry.delete(key);
    return deleted;
  } catch (error) {
    logger.error('Cache delete error for key', key, ':', error.message);
    return false;
  }
};

const flushCache = async () => {
  try {
    cache.clear();
    cacheExpiry.clear();
    logger.info('Cache cleared successfully');
    return true;
  } catch (error) {
    logger.error('Cache flush error:', error.message);
    return false;
  }
};

const getCacheStats = () => {
  const now = Date.now();
  let expiredCount = 0;
  
  for (const expireTime of cacheExpiry.values()) {
    if (now > expireTime) {
      expiredCount++;
    }
  }
  
  return {
    totalEntries: cache.size,
    activeEntries: cache.size - expiredCount,
    expiredEntries: expiredCount,
    status: 'healthy'
  };
};

// Cleanup on process exit
const cleanup = () => {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }
  cache.clear();
  cacheExpiry.clear();
  logger.info('Cache cleanup completed');
};

process.on('SIGTERM', cleanup);
process.on('SIGINT', cleanup);

module.exports = {
  getCached,
  setCached,
  deleteCached,
  flushCache,
  getCacheStats,
  cleanup
};