require('dotenv').config(); // Load environment variables

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const logger = require('./utils/logger');
const { getSupabaseClient, initializeSupabase } = require('./config/database');
const { initializeCloudinary, cloudinary } = require('./config/cloudinary');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandlers');
const { authenticateToken } = require('./middleware/auth');
const { scheduleReminders } = require('./scripts/reminders');
const { initializeRedis } = require('./config/cache');
const { initializeRealtime } = require('./config/realtime');

// Initialize services once
initializeSupabase();
initializeCloudinary();
// initializeRedis();
initializeRealtime();
scheduleReminders();

// Express app setup
const app = express();
const PORT = process.env.PORT || 3000;

// Swagger docs
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Maternity Monitoring API',
      version: '1.0.0',
      description: 'API for maternity monitoring mobile application',
    },
    servers: [{ url: process.env.API_BASE_URL || `http://localhost:${PORT}` }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: ['./routes/*.js'],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
    },
  },
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(compression());
app.use(morgan('combined', {
  stream: { write: message => logger.info(message.trim()) }
}));
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
  optionsSuccessStatus: 200
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const supabase = getSupabaseClient();
    const { error: dbError } = await supabase.from('users').select('id').limit(1);

    const cloudinaryStatus = await new Promise((resolve) => {
      cloudinary.api.ping((error, result) => {
        if (error || !result || result.status !== 'ok') {
          resolve(false);
        } else {
          resolve(true);
        }
      });
    });

    const status = !dbError && cloudinaryStatus ? 'OK' : 'DEGRADED';

    res.status(status === 'OK' ? 200 : 503).json({
      status,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      services: {
        database: !dbError ? 'OK' : 'ERROR',
        cloudinary: cloudinaryStatus ? 'OK' : 'ERROR',
      }
    });
  } catch (error) {
    logger.error('Health check error:', error);
    res.status(503).json({ status: 'ERROR', error: 'Health check failed' });
  }
});


// Routes
const authRoutes = require('./routes/auth');
const pregnancyRoutes = require('./routes/pregnancy');
const kickCountRoutes = require('./routes/kickCount');
const healthTipsRoutes = require('./routes/healthTips');
const appointmentRoutes = require('./routes/appointments');
const wearableRoutes = require('./routes/wearable');
const emergencyRoutes = require('./routes/emergency');
const forumRoutes = require('./routes/forum');
// const adminRoutes = require('./routes/admin');
// const notificationRoutes = require('./routes/notifications');

app.use('/api/auth', authRoutes);
app.use('/api/pregnancy', authenticateToken, pregnancyRoutes);
app.use('/api/kick-count', authenticateToken, kickCountRoutes);
app.use('/api/health-tips', authenticateToken, healthTipsRoutes);
app.use('/api/appointments', authenticateToken, appointmentRoutes);
app.use('/api/wearable', authenticateToken, wearableRoutes);
app.use('/api/emergency', authenticateToken, emergencyRoutes);
app.use('/api/forum', authenticateToken, forumRoutes);
// app.use('/api/admin', authenticateToken, adminRoutes);
// app.use('/api/notifications', authenticateToken, notificationRoutes);

// Error handlers
app.use(notFoundHandler);
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  logger.info(`🚀 Maternity Monitoring Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
