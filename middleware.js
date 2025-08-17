// middleware.js - Custom middleware functions
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');

// Security middleware
const securityMiddleware = () => {
  return [
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }),
    
    // Rate limiting
    rateLimit({
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
      message: {
        error: 'Too many requests from this IP, please try again later.'
      },
      standardHeaders: true,
      legacyHeaders: false,
    }),
    
    // Logging
    morgan('combined')
  ];
};

// Request validation middleware
const validateRequest = (requiredFields) => {
  return (req, res, next) => {
    const missingFields = [];
    
    for (const field of requiredFields) {
      if (!req.body[field] || req.body[field].toString().trim() === '') {
        missingFields.push(field);
      }
    }
    
    if (missingFields.length > 0) {
      return res.status(400).json({
        error: 'Missing required fields',
        missingFields: missingFields
      });
    }
    
    next();
  };
};

// Database connection check middleware
const checkDbConnection = async (req, res, next) => {
  try {
    const sql = require('mssql');
    const pool = sql.globalPool;
    
    if (!pool || !pool.connected) {
      return res.status(503).json({
        error: 'Database connection unavailable'
      });
    }
    
    next();
  } catch (error) {
    return res.status(503).json({
      error: 'Database connection error',
      message: error.message
    });
  }
};

// Response formatting middleware
const formatResponse = (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    // Add timestamp to all responses
    if (typeof data === 'object' && data !== null) {
      try {
        const parsed = typeof data === 'string' ? JSON.parse(data) : data;
        parsed.timestamp = new Date().toISOString();
        return originalSend.call(this, JSON.stringify(parsed));
      } catch (e) {
        // If parsing fails, send original data
        return originalSend.call(this, data);
      }
    }
    return originalSend.call(this, data);
  };
  
  next();
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error details:', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    body: req.body,
    timestamp: new Date().toISOString()
  });

  // SQL Server specific errors
  if (err.number) {
    switch (err.number) {
      case 2: // Connection timeout
        return res.status(503).json({
          error: 'Database connection timeout',
          message: 'Please try again later'
        });
      case 18456: // Login failed
        return res.status(500).json({
          error: 'Database authentication failed'
        });
      case 2627: // Unique constraint violation
        return res.status(409).json({
          error: 'Duplicate entry',
          message: 'Record with this information already exists'
        });
      default:
        return res.status(500).json({
          error: 'Database error',
          message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
        });
    }
  }

  // Default error response
  const status = err.status || err.statusCode || 500;
  res.status(status).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// Request logging middleware
const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  // Log request
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`, {
    body: req.body,
    query: req.query,
    params: req.params,
    userAgent: req.get('User-Agent'),
    ip: req.ip
  });
  
  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - ${res.statusCode} (${duration}ms)`);
  });
  
  next();
};

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      process.env.CORS_ORIGIN
    ].filter(Boolean);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

module.exports = {
  securityMiddleware,
  validateRequest,
  checkDbConnection,
  formatResponse,
  errorHandler,
  requestLogger,
  corsOptions
};