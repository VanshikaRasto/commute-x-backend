const sql = require('mssql');

const dbConfig = {
  user: process.env.DB_USER || 'sa',
  password: process.env.DB_PASSWORD || 'Galaxy@3017',
  server: process.env.DB_SERVER || 'localhost',
  database: process.env.DB_DATABASE || 'DB_CAB_BOOKING',
  port: parseInt(process.env.DB_PORT) || 1433,
  options: {
    encrypt: false,
    trustServerCertificate: true,
    enableArithAbort: true,
    connectionTimeout: 30000,
    requestTimeout: 30000
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

let pool;

const initializePool = async () => {
  if (!pool) {
    try {
      pool = await sql.connect(dbConfig);
      console.log('Database pool connected for updateRequestStatus service');
    } catch (error) {
      console.error('Failed to connect to database in updateRequestStatus service:', error);
      throw error;
    }
  }
  return pool;
};

const updateCabRequestStatus = async (requestId, newStatus, updatedBy = 'system') => {
  try {
    console.log(`Attempting to update request ${requestId} to status ${newStatus} by ${updatedBy}`);
    
    if (!requestId || !newStatus) {
      return {
        success: false,
        message: 'Request ID and status are required'
      };
    }

    const validStatuses = ['PENDING', 'ACCEPTED', 'REJECTED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'];
    if (!validStatuses.includes(newStatus)) {
      return {
        success: false,
        message: `Invalid status. Must be one of: ${validStatuses.join(', ')}`
      };
    }

    const dbPool = await initializePool();
    
    const checkResult = await dbPool.request()
      .input('requestId', sql.Int, parseInt(requestId))
      .query('SELECT Id, Status FROM Cab_Requests WHERE Id = @requestId');

    if (checkResult.recordset.length === 0) {
      return {
        success: false,
        message: `Request with ID ${requestId} not found`
      };
    }

    const currentStatus = checkResult.recordset[0].Status;
    console.log(`Current status: ${currentStatus}, New status: ${newStatus}`);

    const updateResult = await dbPool.request()
      .input('requestId', sql.Int, parseInt(requestId))
      .input('newStatus', sql.VarChar, newStatus)
      .input('updatedBy', sql.VarChar, updatedBy)
      .input('updatedAt', sql.DateTime, new Date())
      .query(`
        UPDATE Cab_Requests 
        SET Status = @newStatus, 
            Updated_By = @updatedBy, 
            Updated_at = @updatedAt
        WHERE Id = @requestId
      `);

    if (updateResult.rowsAffected[0] > 0) {
      console.log(`Successfully updated request ${requestId} from ${currentStatus} to ${newStatus}`);
      return {
        success: true,
        message: `Request status updated from ${currentStatus} to ${newStatus}`,
        data: {
          requestId: parseInt(requestId),
          oldStatus: currentStatus,
          newStatus: newStatus,
          updatedBy: updatedBy,
          updatedAt: new Date()
        }
      };
    } else {
      return {
        success: false,
        message: 'No rows were updated'
      };
    }

  } catch (error) {
    console.error('Error in updateCabRequestStatus:', {
      error: error.message,
      stack: error.stack,
      requestId,
      newStatus,
      updatedBy
    });

    return {
      success: false,
      message: 'Database error occurred while updating request status',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    };
  }
};

module.exports = updateCabRequestStatus;