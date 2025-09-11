require('dotenv').config();
const sql = require('mssql');
const logger = require('./logger');

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  port: parseInt(process.env.DB_PORT) || 1433,
  options: {
    encrypt: process.env.DB_ENCRYPT === 'true',
    trustServerCertificate: process.env.DB_TRUST_SERVER_CERTIFICATE === 'true',
    enableArithAbort: true,
    requestTimeout: parseInt(process.env.DB_TIMEOUT) || 30000
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

class DatabaseConnection {
  constructor() {
    this.pool = null;
    this.isConnected = false;
  }

  async connect() {
    try {
      logger.connectionEvent('connection attempt started');
      const startTime = Date.now();
      
      this.pool = await sql.connect(dbConfig);
      this.isConnected = true;
      
      const duration = Date.now() - startTime;
      logger.connectionEvent('connected successfully', `to ${process.env.DB_SERVER}/${process.env.DB_DATABASE} (${duration}ms)`);
      
      return this.pool;
    } catch (error) {
      this.isConnected = false;
      logger.error(`Database connection failed: ${error.message}`, {
        operation: 'CONNECTION',
        error: error.message
      });
      throw error;
    }
  }

  async disconnect() {
    try {
      if (this.pool) {
        await this.pool.close();
        this.isConnected = false;
        logger.connectionEvent('disconnected successfully');
      }
    } catch (error) {
      logger.error(`Error during disconnection: ${error.message}`, {
        operation: 'DISCONNECTION'
      });
      throw error;
    }
  }

  getPool() {
    if (!this.isConnected || !this.pool) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.pool;
  }

  async testConnection() {
    try {
      logger.operationStart('CONNECTION_TEST');
      const startTime = Date.now();
      
      const pool = await this.connect();
      const result = await pool.request().query('SELECT 1 as test');
      
      const duration = Date.now() - startTime;
      logger.operationComplete('CONNECTION_TEST', duration, '- Database is accessible');
      
      await this.disconnect();
      return true;
    } catch (error) {
      logger.error(`Connection test failed: ${error.message}`, {
        operation: 'CONNECTION_TEST'
      });
      return false;
    }
  }
}

module.exports = new DatabaseConnection();