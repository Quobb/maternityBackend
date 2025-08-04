const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'maternity-monitoring' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// utils/logger.js (Add to existing file)
const auditLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'maternity-monitoring-audit' },
  transports: [
    new winston.transports.File({ filename: 'logs/audit.log' }),
  ],
});


// Add to all sensitive endpoints (e.g., pregnancy, wearable)
const auditLog = (action, userId, details) => {
  auditLogger.info({ action, userId, details, timestamp: new Date().toISOString() });
};

module.exports = logger;
