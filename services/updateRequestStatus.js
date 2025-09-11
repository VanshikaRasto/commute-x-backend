const sql = require('mssql');
const db = require('./dbConfig');
const logger = require('./logger');

/**
 * Updates the status of a cab request
 * @param {number} requestId - The ID of the request to update
 * @param {string} status - New status (e.g., 'ACCEPTED', 'REJECTED')
 * @param {string} updatedBy - Username of the admin making the update
 * @returns {Promise<object>} Result of the update operation
 */
async function updateCabRequestStatus(requestId, status, updatedBy) {
  if (!requestId || !status || !updatedBy) {
    throw new Error('Missing required parameters: requestId, status, and updatedBy are required');
  }

  try {
    await db.connect();
    const pool = db.getPool();

    const result = await pool.request()
      .input('requestId', sql.Int, requestId)
      .input('status', sql.NVarChar(50), status)
      .input('updatedBy', sql.NVarChar(50), updatedBy)
      .query(`
        UPDATE Cab_Requests
        SET 
          Status = @status,
          Updated_at = GETDATE(),
          Updated_By = @updatedBy
        WHERE Id = @requestId;
        
        SELECT @@ROWCOUNT as rowsAffected;
      `);

    return {
      success: result.recordset[0].rowsAffected > 0,
      rowsAffected: result.recordset[0].rowsAffected,
      message: result.recordset[0].rowsAffected > 0 
        ? 'Request updated successfully' 
        : 'No request found with the specified ID'
    };
  } catch (error) {
    logger.error('Error updating cab request status:', error);
    throw error;
  } finally {
    await db.disconnect();
  }
}

module.exports = updateCabRequestStatus;