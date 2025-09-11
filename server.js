// server.js - Complete Backend Server with Role-based Authentication
const express = require('express');
const cors = require('cors');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// Change this line at the top of server.js
const updateCabRequestStatus = require('./services/updateRequestStatus');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Database Configuration
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

// Global database pool
let poolPromise;

// Initialize Database Connection
const initializeDatabase = async () => {
  try {
    poolPromise = sql.connect(dbConfig);
    await poolPromise;
    console.log('Connected to SQL Server Database');
  } catch (error) {
    console.error('Database connection failed:', error);
    process.exit(1);
  }
};

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Role-based middleware
const checkRole = (allowedRoles) => {
  return (req, res, next) => {
    const userRole = req.user.role;
    
    if (allowedRoles.includes(userRole)) {
      next();
    } else {
      return res.status(403).json({ error: 'Access denied: Insufficient permissions' });
    }
  };
};

// ===================== AUTH ROUTES =====================

// Login Route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const pool = await poolPromise;
    const result = await pool.request()
      .input('username', sql.VarChar, username)
      .query(`
        SELECT Id, U_Name, Email_ID, u_Password, Hash_Password, Role_Id, IsActive 
        FROM Users 
        WHERE U_Name = @username OR Email_ID = @username
      `);

    if (result.recordset.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.recordset[0];

    // Check password (both plain and hashed)
    const isValidPassword = 
      password === user.u_Password || 
      (user.Hash_Password && await bcrypt.compare(password, user.Hash_Password));

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.IsActive) {
      return res.status(401).json({ error: 'Account is deactivated' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.Id, username: user.U_Name, role: user.Role_Id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Update last login
    await pool.request()
      .input('userId', sql.Int, user.Id)
      .query('UPDATE Users SET Last_Login_at = GETDATE(), IsLoggedIn = 1 WHERE Id = @userId');

    res.json({
      success: true,
      token,
      user: {
        id: user.Id,
        name: user.U_Name,
        email: user.Email_ID,
        role: user.Role_Id
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Logout Route
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const pool = await poolPromise;
    await pool.request()
      .input('userId', sql.Int, req.user.userId)
      .query('UPDATE Users SET IsLoggedIn = 0 WHERE Id = @userId');

    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Server error during logout' });
  }
});

// ===================== USER ROUTES =====================

// Create User
app.post('/api/users', async (req, res) => {
  try {
    const {
      name, email, phone, password, address, latitude, longitude,
      type = 'user', status = 'Active',
      departmentId, regisNo, contactNo, deskExtNo, deskNo,
      roleId, isAvailable = true, isAccountVerified = true
    } = req.body;

    console.log('Received registration data:', {
      name, email, phone, departmentId, regisNo, roleId, address
    });

    if (!name || !email || !phone || !password || !address || !departmentId || !regisNo) {
      return res.status(400).json({ 
        error: 'All required fields must be provided',
        required: ['name', 'email', 'phone', 'password', 'address', 'departmentId', 'regisNo']
      });
    }

    const pool = await poolPromise;

    // Check if user already exists
    const existingUser = await pool.request()
      .input('email', sql.VarChar, email)
      .input('phone', sql.VarChar, phone)
      .input('regisNo', sql.VarChar, regisNo)
      .query(`
        SELECT Id, Email_ID, Mobile_No, Regis_No 
        FROM Users 
        WHERE Email_ID = @email OR Mobile_No = @phone OR Regis_No = @regisNo
      `);

    if (existingUser.recordset.length > 0) {
      const existing = existingUser.recordset[0];
      if (existing.Email_ID === email) {
        return res.status(400).json({ error: 'User with this email already exists' });
      }
      if (existing.Mobile_No === phone) {
        return res.status(400).json({ error: 'User with this phone number already exists' });
      }
      if (existing.Regis_No === regisNo) {
        return res.status(400).json({ error: 'User with this registration number already exists' });
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Calculate distance from office
    const officeLat = 28.6139;
    const officeLng = 77.2090;
    const userLat = parseFloat(latitude);
    const userLng = parseFloat(longitude);

    let distance = 0;
    if (userLat && userLng) {
      const R = 6371;
      const dLat = (userLat - officeLat) * Math.PI / 180;
      const dLon = (userLng - officeLng) * Math.PI / 180;
      const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                Math.cos(officeLat * Math.PI/180) * Math.cos(userLat * Math.PI/180) *
                Math.sin(dLon/2) * Math.sin(dLon/2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
      distance = (R * c).toFixed(2);
    }

    // Insert user
    const result = await pool.request()
      .input('departmentId', sql.Int, parseInt(departmentId))
      .input('regisNo', sql.VarChar, regisNo)
      .input('uName', sql.VarChar, name)
      .input('email', sql.VarChar, email)
      .input('mobile', sql.VarChar, phone)
      .input('contactNo', sql.VarChar, contactNo || phone)
      .input('deskExtNo', sql.VarChar, deskExtNo || null)
      .input('deskNo', sql.VarChar, deskNo || null)
      .input('password', sql.VarChar, password)
      .input('hashPassword', sql.VarChar, hashedPassword)
      .input('address', sql.VarChar, address)
      .input('lat', sql.Decimal(10, 8), userLat || null)
      .input('lng', sql.Decimal(11, 8), userLng || null)
      .input('distance', sql.Decimal(10, 2), distance)
      .input('isActive', sql.Bit, status === 'Active' ? 1 : 0)
      .input('isAvailable', sql.Bit, isAvailable ? 1 : 0)
      .input('roleId', sql.Int, parseInt(roleId) || (type === 'admin' ? 1 : 2))
      .input('isLoggedIn', sql.Bit, 0)
      .input('isAccountVerified', sql.Bit, isAccountVerified ? 1 : 0)
      .input('createdBy', sql.VarChar, '1')
      .query(`
        INSERT INTO Users (
          Department_Id, Regis_No, U_Name, Email_ID, Mobile_No, Contact_No,
          Desk_ExtNo, Desk_No, u_Password, Hash_Password, U_Address, Lat_Address, Long_Address, Distance,
          IsActive, IsAvailable, Role_Id, IsLoggedIn, IsAccount_Verified,
          Created_By, Created_at
        ) VALUES (
          @departmentId, @regisNo, @uName, @email, @mobile, @contactNo,
          @deskExtNo, @deskNo, @password, @hashPassword, @address, @lat, @lng, @distance,
          @isActive, @isAvailable, @roleId, @isLoggedIn, @isAccountVerified,
          @createdBy, GETDATE()
        );
        SELECT SCOPE_IDENTITY() AS Id;
      `);

    const userId = result.recordset[0].Id;

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      userId: userId,
      data: {
        id: userId,
        regisNo: regisNo,
        name,
        email,
        phone,
        distance: `${distance} km`,
        departmentId: parseInt(departmentId),
        roleId: parseInt(roleId),
        status: status
      }
    });

  } catch (error) {
    console.error('Create user error:', error);
    
    if (error.number === 515) {
      res.status(500).json({ 
        error: 'Database constraint error: Missing required field'
      });
    } else if (error.number === 2627) {
      res.status(409).json({ 
        error: 'Duplicate entry: User with this information already exists'
      });
    } else if (error.number === 547) {
      res.status(400).json({ 
        error: 'Invalid reference: Department ID does not exist'
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to create user',
        details: error.message
      });
    }
  }
});

// Get All Users
app.get('/api/users', async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT 
        Id, Department_Id, Regis_No, U_Name, Email_ID, Mobile_No, Contact_No,
        Desk_ExtNo, Desk_No, U_Address, Lat_Address, Long_Address, Distance, 
        IsActive, IsAvailable, Role_Id, IsAccount_Verified, Created_at, Last_Login_at
      FROM Users
      ORDER BY Created_at DESC
    `);

    const users = result.recordset.map(user => ({
      id: user.Id,
      departmentId: user.Department_Id,
      regisNo: user.Regis_No,
      name: user.U_Name,
      email: user.Email_ID,
      phone: user.Mobile_No,
      contactNo: user.Contact_No,
      deskExtNo: user.Desk_ExtNo,
      deskNo: user.Desk_No,
      address: user.U_Address,
      latitude: user.Lat_Address,
      longitude: user.Long_Address,
      distance: user.Distance,
      status: user.IsActive ? 'Active' : 'Inactive',
      isAvailable: user.IsAvailable,
      role: user.Role_Id === 1 ? 'Admin' : user.Role_Id === 2 ? 'Employee' : user.Role_Id === 3 ? 'Manager' : 'Guest',
      isVerified: user.IsAccount_Verified,
      joinDate: user.Created_at,
      lastLogin: user.Last_Login_at
    }));

    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ===================== VENDOR ROUTES =====================

// Create Vendor
app.post('/api/vendors', async (req, res) => {
  try {
    const {
      vendorName, vendorPhoneNo, vendorEmailId, vendorAddress,
      vendorAPI, activeDeactive = false
    } = req.body;

    if (!vendorName || !vendorPhoneNo || !vendorEmailId || !vendorAddress) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }

    const pool = await poolPromise;

    const existingVendor = await pool.request()
      .input('email', sql.VarChar, vendorEmailId)
      .input('phone', sql.VarChar, vendorPhoneNo)
      .query('SELECT Id FROM Mst_Vendor WHERE Vendor_EmailId = @email OR Vendor_Phone_No = @phone');

    if (existingVendor.recordset.length > 0) {
      return res.status(400).json({ error: 'Vendor with this email or phone already exists' });
    }

    const result = await pool.request()
      .input('vendorName', sql.VarChar, vendorName)
      .input('vendorPhone', sql.VarChar, vendorPhoneNo)
      .input('vendorEmail', sql.VarChar, vendorEmailId)
      .input('vendorAddress', sql.VarChar, vendorAddress)
      .input('vendorAPI', sql.VarChar, vendorAPI || '')
      .input('isActive', sql.Bit, activeDeactive ? 1 : 0)
      .input('createdBy', sql.VarChar, '1')
      .query(`
        INSERT INTO Mst_Vendor (
          Vendor_Name, Vendor_Phone_No, Vendor_EmailId, Vendor_Address,
          Vendor_API, IsActive, Created_By, Created_at
        ) VALUES (
          @vendorName, @vendorPhone, @vendorEmail, @vendorAddress,
          @vendorAPI, @isActive, @createdBy, GETDATE()
        );
        SELECT SCOPE_IDENTITY() AS Id;
      `);

    const vendorId = result.recordset[0].Id;

    res.status(201).json({
      success: true,
      message: 'Vendor created successfully',
      vendorId: vendorId
    });

  } catch (error) {
    console.error('Create vendor error:', error);
    res.status(500).json({ error: 'Failed to create vendor' });
  }
});

// Get All Vendors
app.get('/api/vendors', async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT 
        Id, Vendor_Name, Vendor_Phone_No, Vendor_EmailId,
        Vendor_Address, Vendor_API, IsActive, Created_at
      FROM Mst_Vendor
      ORDER BY Created_at DESC
    `);

    const vendors = result.recordset.map(vendor => ({
      id: vendor.Id,
      name: vendor.Vendor_Name,
      phone: vendor.Vendor_Phone_No,
      email: vendor.Vendor_EmailId,
      address: vendor.Vendor_Address,
      api: vendor.Vendor_API,
      status: vendor.IsActive ? 'Active' : 'Inactive',
      createdAt: vendor.Created_at
    }));

    res.json({ success: true, data: vendors });
  } catch (error) {
    console.error('Get vendors error:', error);
    res.status(500).json({ error: 'Failed to fetch vendors' });
  }
});

// ===================== VEHICLE ROUTES =====================

// Create Vehicle
app.post('/api/vehicles', async (req, res) => {
  try {
    const {
      vendorName, vendorPhoneNo, vendorEmailId, vendorAddress,
      vehicleNo, vehicleType, hireType, vehicleModel,
      insuranceExpireDate, pucExpireDate, activeDeactive = false
    } = req.body;

    if (!vehicleNo || !vehicleType || !vehicleModel) {
      return res.status(400).json({ error: 'Vehicle number, type, and model are required' });
    }

    const pool = await poolPromise;

    const existingVehicle = await pool.request()
      .input('vehicleNo', sql.VarChar, vehicleNo)
      .query('SELECT Id FROM Mst_Vehicle WHERE Vehicle_No = @vehicleNo');

    if (existingVehicle.recordset.length > 0) {
      return res.status(400).json({ error: 'Vehicle with this number already exists' });
    }

    const result = await pool.request()
      .input('vendorName', sql.VarChar, vendorName || '')
      .input('vendorPhone', sql.VarChar, vendorPhoneNo || '')
      .input('vendorEmail', sql.VarChar, vendorEmailId || '')
      .input('vendorAddress', sql.VarChar, vendorAddress || '')
      .input('vehicleNo', sql.VarChar, vehicleNo)
      .input('vehicleType', sql.VarChar, vehicleType)
      .input('hireType', sql.VarChar, hireType || 'Custom')
      .input('vehicleModel', sql.VarChar, vehicleModel)
      .input('insurance', sql.Date, insuranceExpireDate || null)
      .input('puc', sql.Date, pucExpireDate || null)
      .input('isActive', sql.Bit, activeDeactive ? 1 : 0)
      .input('createdBy', sql.VarChar, '1')
      .query(`
        INSERT INTO Mst_Vehicle (
          Vendor_Name, Vendor_Phone_No, Vendor_EmailId, Vendor_Address,
          Vehicle_No, Vehicle_Type, Vehicle_Hire_Type, Vehicle_Model,
          Insurance_Expire, PUC_Expire, IsActive, Created_By, Created_at
        ) VALUES (
          @vendorName, @vendorPhone, @vendorEmail, @vendorAddress,
          @vehicleNo, @vehicleType, @hireType, @vehicleModel,
          @insurance, @puc, @isActive, @createdBy, GETDATE()
        );
        SELECT SCOPE_IDENTITY() AS Id;
      `);

    const vehicleId = result.recordset[0].Id;

    res.status(201).json({
      success: true,
      message: 'Vehicle created successfully',
      vehicleId: vehicleId
    });

  } catch (error) {
    console.error('Create vehicle error:', error);
    res.status(500).json({ error: 'Failed to create vehicle' });
  }
});

// Get All Vehicles
app.get('/api/vehicles', async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT 
        Id, Vehicle_No, Vehicle_Type, Vehicle_Model,
        Vehicle_Hire_Type, Insurance_Expire, PUC_Expire,
        IsActive, Created_at
      FROM Mst_Vehicle
      ORDER BY Created_at DESC
    `);

    const vehicles = result.recordset.map(vehicle => ({
      id: vehicle.Id,
      number: vehicle.Vehicle_No,
      type: vehicle.Vehicle_Type,
      model: vehicle.Vehicle_Model,
      hireType: vehicle.Vehicle_Hire_Type,
      insuranceExpiry: vehicle.Insurance_Expire,
      pucExpiry: vehicle.PUC_Expire,
      status: vehicle.IsActive ? 'Available' : 'Inactive',
      createdAt: vehicle.Created_at
    }));

    res.json({ success: true, data: vehicles });
  } catch (error) {
    console.error('Get vehicles error:', error);
    res.status(500).json({ error: 'Failed to fetch vehicles' });
  }
});

// ===================== DRIVER ROUTES =====================

// Create Driver
app.post('/api/drivers', async (req, res) => {
  try {
    const {
      driverName, dob, age, gender, address, phone, email,
      licenseNumber, issueDate, expiryDate, experience,
      emergencyName, emergencyPhone
    } = req.body;

    if (!driverName || !phone || !licenseNumber || !experience) {
      return res.status(400).json({ error: 'Driver name, phone, license number, and experience are required' });
    }

    const pool = await poolPromise;

    const existingDriver = await pool.request()
      .input('phone', sql.VarChar, phone)
      .input('license', sql.VarChar, licenseNumber)
      .query('SELECT Id FROM Mst_Driver WHERE Driver_Phone_No = @phone OR DL_No = @license');

    if (existingDriver.recordset.length > 0) {
      return res.status(400).json({ error: 'Driver with this phone or license number already exists' });
    }

    const result = await pool.request()
      .input('driverName', sql.VarChar, driverName)
      .input('driverPhone', sql.VarChar, phone)
      .input('driverAddress', sql.VarChar, address || '')
      .input('emergencyContact', sql.VarChar, emergencyName || '')
      .input('emergencyPhone', sql.VarChar, emergencyPhone || '')
      .input('gender', sql.VarChar, gender || '')
      .input('dob', sql.Date, dob || null)
      .input('experience', sql.VarChar, experience.toString())
      .input('dlNo', sql.VarChar, licenseNumber)
      .input('dlExpire', sql.Date, expiryDate || null)
      .input('isActive', sql.Bit, 1)
      .input('isAvailable', sql.Bit, 1)
      .input('createdBy', sql.VarChar, '1')
      .query(`
        INSERT INTO Mst_Driver (
          Driver_Name, Driver_Phone_No, Driver_Address,
          Emergency_Contact_Person, Emergency_Contact_No, Gender, DOB,
          Experience, DL_No, DL_Expire, IsActive, IsAvailable,
          Created_By, Created_at
        ) VALUES (
          @driverName, @driverPhone, @driverAddress,
          @emergencyContact, @emergencyPhone, @gender, @dob,
          @experience, @dlNo, @dlExpire, @isActive, @isAvailable,
          @createdBy, GETDATE()
        );
        SELECT SCOPE_IDENTITY() AS Id;
      `);

    const driverId = result.recordset[0].Id;

    res.status(201).json({
      success: true,
      message: 'Driver created successfully',
      driverId: driverId
    });

  } catch (error) {
    console.error('Create driver error:', error);
    res.status(500).json({ error: 'Failed to create driver' });
  }
});

// Get All Drivers
app.get('/api/drivers', async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT 
        Id, Driver_Name, Driver_Phone_No, DL_No, Experience,
        IsActive, IsAvailable, Created_at
      FROM Mst_Driver
      ORDER BY Created_at DESC
    `);

    const drivers = result.recordset.map(driver => ({
      id: driver.Id,
      name: driver.Driver_Name,
      phone: driver.Driver_Phone_No,
      license: driver.DL_No,
      experience: `${driver.Experience} years`,
      status: driver.IsAvailable ? 'Available' : (driver.IsActive ? 'On Trip' : 'Inactive'),
      createdAt: driver.Created_at
    }));

    res.json({ success: true, data: drivers });
  } catch (error) {
    console.error('Get drivers error:', error);
    res.status(500).json({ error: 'Failed to fetch drivers' });
  }
});

// ===================== ROUTE ROUTES =====================

// Create Route
app.post('/api/routes', async (req, res) => {
  try {
    const {
      routeId, name, origin, destination, estimatedDistanceKm,
      estimatedTimeMinutes, isActive = true, stops = []
    } = req.body;

    console.log('Received route data:', {
      routeId, name, origin, destination, estimatedDistanceKm, estimatedTimeMinutes, stops: stops.length
    });

    if (!routeId || !name || !origin || !destination || !estimatedDistanceKm || !estimatedTimeMinutes) {
      return res.status(400).json({ error: 'All route information fields are required' });
    }

    const pool = await poolPromise;

    const existingRoute = await pool.request()
      .input('routeNo', sql.VarChar, routeId)
      .query('SELECT Id FROM Mst_Routes WHERE Route_No = @routeNo');

    if (existingRoute.recordset.length > 0) {
      return res.status(400).json({ error: 'Route with this ID already exists' });
    }

    const transaction = new sql.Transaction(pool);

    try {
      await transaction.begin();

      const totalMinutes = parseInt(estimatedTimeMinutes);
      const hours = Math.floor(totalMinutes / 60);
      const minutes = totalMinutes % 60;
      const timeString = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:00`;

      const routeResult = await transaction.request()
        .input('routeNo', sql.VarChar, routeId)
        .input('routeName', sql.VarChar, name)
        .input('routeSource', sql.VarChar, origin)
        .input('routeDestination', sql.VarChar, destination)
        .input('estimatedDistance', sql.Int, parseInt(estimatedDistanceKm))
        .input('estimatedTime', sql.VarChar, timeString)
        .input('isActive', sql.Bit, isActive ? 1 : 0)
        .input('createdBy', sql.VarChar, '1')
        .query(`
          INSERT INTO Mst_Routes (
            Route_No, Route_Name, Route_Source, Route_Destination,
            Eastimated_Distance, Eastimated_Time, IsActive,
            Created_By, Created_at
          ) VALUES (
            @routeNo, @routeName, @routeSource, @routeDestination,
            @estimatedDistance, @estimatedTime, @isActive,
            @createdBy, GETDATE()
          );
          SELECT SCOPE_IDENTITY() AS Id;
        `);

      const newRouteId = routeResult.recordset[0].Id;

      let stopsAdded = 0;
      if (stops && stops.length > 0) {
        for (let i = 0; i < stops.length; i++) {
          const stop = stops[i];
          
          const stopResult = await transaction.request()
            .input('stopName', sql.VarChar, stop.stopName)
            .input('stopAddress', sql.VarChar, stop.address)
            .input('stopLat', sql.VarChar, stop.lat.toString())
            .input('stopLong', sql.VarChar, stop.lng.toString())
            .input('isActive', sql.Bit, 1)
            .input('createdBy', sql.VarChar, '1')
            .query(`
              INSERT INTO Mst_Stoppage (
                Stop_Name, Stop_Address, Stop_Lat, Stop_Long,
                IsActive, Created_By, Created_at
              ) VALUES (
                @stopName, @stopAddress, @stopLat, @stopLong,
                @isActive, @createdBy, GETDATE()
              );
              SELECT SCOPE_IDENTITY() AS Id;
            `);

          const stoppageId = stopResult.recordset[0].Id;

          await transaction.request()
            .input('routeId', sql.Int, newRouteId)
            .input('stoppageId', sql.Int, stoppageId)
            .input('isActive', sql.Bit, 1)
            .input('createdBy', sql.VarChar, '1')
            .query(`
              INSERT INTO Mstmap_Route_Stoppage (
                Route_Id, Stoppage_Id, IsActive, Created_By, Created_at
              ) VALUES (
                @routeId, @stoppageId, @isActive, @createdBy, GETDATE()
              );
            `);

          stopsAdded++;
        }
      }

      await transaction.commit();

      res.status(201).json({
        success: true,
        message: 'Route created successfully',
        routeId: newRouteId,
        stopsAdded: stopsAdded
      });

    } catch (error) {
      await transaction.rollback();
      throw error;
    }

  } catch (error) {
    console.error('Create route error:', error);
    res.status(500).json({ 
      error: 'Failed to create route',
      details: error.message
    });
  }
});

// Get All Routes
app.get('/api/routes', async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT 
        r.Id, r.Route_No, r.Route_Name, r.Route_Source, r.Route_Destination,
        r.Eastimated_Distance, r.Eastimated_Time, r.IsActive, r.Created_at,
        COUNT(mrs.Stoppage_Id) as StopCount
      FROM Mst_Routes r
      LEFT JOIN Mstmap_Route_Stoppage mrs ON r.Id = mrs.Route_Id AND mrs.IsActive = 1
      GROUP BY r.Id, r.Route_No, r.Route_Name, r.Route_Source, r.Route_Destination,
               r.Eastimated_Distance, r.Eastimated_Time, r.IsActive, r.Created_at
      ORDER BY r.Created_at DESC
    `);

    const routes = result.recordset.map(route => {
      let durationMinutes = 0;
      if (route.Eastimated_Time) {
        const timeStr = route.Eastimated_Time.toString();
        
        if (timeStr.includes(':')) {
          const timeParts = timeStr.split(':');
          if (timeParts.length >= 2) {
            const hours = parseInt(timeParts[0]) || 0;
            const minutes = parseInt(timeParts[1]) || 0;
            durationMinutes = hours * 60 + minutes;
          }
        } else {
          durationMinutes = parseInt(timeStr) || 0;
        }
      }

      return {
        id: route.Id,
        routeNo: route.Route_No,
        name: route.Route_Name,
        source: route.Route_Source,
        destination: route.Route_Destination,
        distance: `${route.Eastimated_Distance} km`,
        duration: `${durationMinutes} mins`,
        status: route.IsActive ? 'Active' : 'Inactive',
        stopCount: route.StopCount,
        createdAt: route.Created_at
      };
    });

    res.json({ success: true, data: routes });
  } catch (error) {
    console.error('Get routes error:', error);
    res.status(500).json({ error: 'Failed to fetch routes' });
  }
});

// ===================== CAB REQUEST ROUTES =====================

// Create Cab Request - FIXED VERSION
app.post('/api/cab-requests', authenticateToken, async (req, res) => {
  try {
    const {
      pickupLocation, pickupLat, pickupLng,
      destination, destinationLat, destinationLng,
      requestedDateTime, contactNumber
    } = req.body;

    if (!pickupLocation || !destination || !requestedDateTime) {
      return res.status(400).json({ error: 'Pickup location, destination, and requested time are required' });
    }

    const pool = await poolPromise;
    const userId = req.user.userId; // Get user ID from the authenticated token

    const result = await pool.request()
      .input('userId', sql.Int, userId)
      .input('pickupLocation', sql.VarChar, pickupLocation)
      .input('pickupLat', sql.Decimal(10, 8), parseFloat(pickupLat) || null)
      .input('pickupLong', sql.Decimal(11, 8), parseFloat(pickupLng) || null)
      .input('destination', sql.VarChar, destination)
      .input('destLat', sql.Decimal(10, 8), parseFloat(destinationLat) || null)
      .input('destLong', sql.Decimal(11, 8), parseFloat(destinationLng) || null)
      .input('requestedDateTime', sql.DateTime, new Date(requestedDateTime))
      .input('status', sql.VarChar, 'PENDING')
      .input('createdBy', sql.VarChar, req.user.name || `User-${userId}`)
      .query(`
        INSERT INTO Cab_Requests (
          User_Id, Pickup_Location, Pickup_Lat, Pickup_Long,
          Destination, Destination_Lat, Destination_Long,
          Requested_DateTime, Status, Created_By, Created_at
        ) VALUES (
          @userId, @pickupLocation, @pickupLat, @pickupLong,
          @destination, @destLat, @destLong,
          @requestedDateTime, @status, @createdBy, GETDATE()
        );
        SELECT SCOPE_IDENTITY() AS Id;
      `);

    const requestId = result.recordset[0].Id;

    res.status(201).json({
      success: true,
      message: 'Cab request created successfully',
      requestId: requestId,
      status: 'PENDING'
    });

  } catch (error) {
    console.error('Create cab request error:', error);
    res.status(500).json({ error: 'Failed to create cab request' });
  }
});

// Get All Cab Requests
app.get('/api/cab-requests', async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT 
        cr.Id, cr.Pickup_Location, cr.Destination,
        cr.Requested_DateTime, cr.Status, cr.Created_at,
        u.U_Name as UserName
      FROM Cab_Requests cr
      LEFT JOIN Users u ON cr.User_Id = u.Id
      ORDER BY cr.Created_at DESC
    `);

    const requests = result.recordset.map(req => ({
      id: req.Id,
      pickupLocation: req.Pickup_Location,
      destination: req.Destination,
      requestedTime: req.Requested_DateTime,
      status: req.Status,
      userName: req.UserName,
      createdAt: req.Created_at
    }));

    res.json({ success: true, data: requests });
  } catch (error) {
    console.error('Get cab requests error:', error);
    res.status(500).json({ error: 'Failed to fetch cab requests' });
  }
});

// Update Cab Request Status and Assign Driver/Vehicle
app.put('/api/cab-requests/:id', authenticateToken, checkRole(['admin', 'dispatcher']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, driverId, vehicleId, adminNotes } = req.body;
    const adminId = req.user.userId;

    const pool = await poolPromise;
    
    // Update the cab request status and assignment
    const result = await pool.request()
      .input('id', sql.Int, id)
      .input('status', sql.NVarChar(50), status)
      .input('driverId', sql.Int, driverId || null)
      .input('vehicleId', sql.Int, vehicleId || null)
      .input('adminId', sql.Int, adminId)
      .input('adminNotes', sql.NVarChar(sql.MAX), adminNotes || null)
      .query(`
        UPDATE Cab_Requests
        SET Status = @status,
            Driver_Id = @driverId,
            Vehicle_Id = @vehicleId,
            Admin_Notes = @adminNotes,
            Updated_By = @adminId,
            Updated_At = GETDATE()
        WHERE Id = @id
        
        SELECT cr.*, 
               u.U_Name as UserName,
               d.Driver_Name as DriverName,
               v.Vehicle_No as VehicleNumber
        FROM Cab_Requests cr
        LEFT JOIN Users u ON cr.User_Id = u.Id
        LEFT JOIN Mst_Driver d ON cr.Driver_Id = d.Id
        LEFT JOIN Mst_Vehicle v ON cr.Vehicle_Id = v.Id
        WHERE cr.Id = @id
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'Cab request not found' });
    }

    const updatedRequest = {
      id: result.recordset[0].Id,
      status: result.recordset[0].Status,
      pickupLocation: result.recordset[0].Pickup_Location,
      destination: result.recordset[0].Destination,
      requestedTime: result.recordset[0].Requested_DateTime,
      status: result.recordset[0].Status,
      driverId: result.recordset[0].Driver_Id,
      driverName: result.recordset[0].DriverName,
      vehicleId: result.recordset[0].Vehicle_Id,
      vehicleNumber: result.recordset[0].VehicleNumber,
      adminNotes: result.recordset[0].Admin_Notes,
      updatedAt: result.recordset[0].Updated_At,
      updatedBy: result.recordset[0].Updated_By
    };

    res.json({ success: true, data: updatedRequest });
  } catch (error) {
    console.error('Update cab request error:', error);
    res.status(500).json({ error: 'Failed to update cab request' });
  }
});

// Update Cab Request Status
app.patch('/api/cab-requests/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const updatedBy = req.user.username || 'system';

    // Input validation
    if (!status) {
      return res.status(400).json({ 
        success: false, 
        message: 'Status is required' 
      });
    }

    // Validate status value
    const validStatuses = ['PENDING', 'ACCEPTED', 'REJECTED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Invalid status. Must be one of: ${validStatuses.join(', ')}`
      });
    }

    // Validate ID
    if (isNaN(parseInt(id))) {
      return res.status(400).json({
        success: false,
        message: 'Invalid request ID'
      });
    }

    // Log the update attempt
    console.log(`Updating request ${id} to status ${status} by ${updatedBy}`);

    const result = await updateCabRequestStatus(id, status, updatedBy);
    
    if (result.success) {
      console.log(`Successfully updated request ${id} to status ${status}`);
      return res.status(200).json({
        success: true,
        message: 'Request status updated successfully',
        data: {
          requestId: id,
          newStatus: status,
          updatedBy,
          updatedAt: new Date().toISOString()
        }
      });
    } else {
      console.warn(`Failed to update request ${id}: ${result.message}`);
      return res.status(404).json({
        success: false,
        message: result.message || 'Failed to update request status',
        requestId: id
      });
    }
  } catch (error) {
    console.error('Error updating request status:', {
      error: error.message,
      stack: error.stack,
      params: req.params,
      body: req.body,
      user: req.user
    });
    
    return res.status(500).json({ 
      success: false, 
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ===================== DASHBOARD ROUTES =====================

// Get Dashboard Stats
app.get('/api/dashboard/stats', async (req, res) => {
  try {
    const pool = await poolPromise;
    
    const [users, vehicles, drivers, routes, requests, vendors] = await Promise.all([
      pool.request().query('SELECT COUNT(*) as count FROM Users WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) as count FROM Mst_Vehicle WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) as count FROM Mst_Driver WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) as count FROM Mst_Routes WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) as count FROM Cab_Requests WHERE Status = \'PENDING\''),
      pool.request().query('SELECT COUNT(*) as count FROM Mst_Vendor WHERE IsActive = 1')
    ]);

    res.json({
      success: true,
      data: {
        users: users.recordset[0].count,
        vehicles: vehicles.recordset[0].count,
        drivers: drivers.recordset[0].count,
        routes: routes.recordset[0].count,
        activeRequests: requests.recordset[0].count,
        vendors: vendors.recordset[0].count
      }
    });

  } catch (error) {
    console.error('Get dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
});

// Get Recent Activities
app.get('/api/dashboard/activities', async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT TOP 10
        'Cab Request' as type,
        CONCAT('New booking from ', ISNULL(u.U_Name, 'Unknown User'), ' to ', cr.Destination) as message,
        cr.Created_at as timestamp
      FROM Cab_Requests cr
      LEFT JOIN Users u ON cr.User_Id = u.Id
      WHERE cr.Created_at >= DATEADD(hour, -24, GETDATE())
      ORDER BY cr.Created_at DESC
    `);

    const activities = result.recordset.map(activity => ({
      type: activity.type.toLowerCase().replace(' ', ''),
      message: activity.message,
      time: getTimeAgo(activity.timestamp)
    }));

    res.json({ success: true, data: activities });
  } catch (error) {
    console.error('Get activities error:', error);
    res.status(500).json({ error: 'Failed to fetch recent activities' });
  }
});




// ===================== HEALTH CHECK =====================

app.get('/api/health', async (req, res) => {
  try {
    const pool = await poolPromise;
    await pool.request().query('SELECT 1');
    res.json({ 
      status: 'healthy', 
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'unhealthy', 
      database: 'disconnected',
      error: error.message 
    });
  }
});

// ===================== UTILITY FUNCTIONS =====================

// Helper function to get time ago
function getTimeAgo(date) {
  const now = new Date();
  const diffInMs = now - new Date(date);
  const diffInMins = Math.floor(diffInMs / (1000 * 60));
  
  if (diffInMins < 1) return 'Just now';
  if (diffInMins < 60) return `${diffInMins}m`;
  
  const diffInHours = Math.floor(diffInMins / 60);
  if (diffInHours < 24) return `${diffInHours}h`;
  
  const diffInDays = Math.floor(diffInHours / 24);
  return `${diffInDays}d`;
}

// Create demo users function
const createDemoUsers = async () => {
  try {
    const pool = await poolPromise;
    
    const existingUsers = await pool.request()
      .query("SELECT COUNT(*) as count FROM Users WHERE U_Name IN ('admin', 'employee', 'manager')");
    
    if (existingUsers.recordset[0].count > 0) {
      console.log('Demo users already exist');
      return;
    }
    
    const demoUsers = [
      {
        name: 'admin',
        email: 'admin@commutex.com',
        phone: '9999999999',
        password: 'admin',
        role: 1,
        regisNo: 'ADMIN001',
        departmentId: 1
      },
      {
        name: 'employee',
        email: 'employee@commutex.com', 
        phone: '8888888888',
        password: 'employee',
        role: 2,
        regisNo: 'EMP001',
        departmentId: 2
      },
      {
        name: 'manager',
        email: 'manager@commutex.com',
        phone: '7777777777', 
        password: 'manager',
        role: 3,
        regisNo: 'MGR001',
        departmentId: 1
      }
    ];
    
    for (const user of demoUsers) {
      const hashedPassword = await bcrypt.hash(user.password, 10);
      
      await pool.request()
        .input('departmentId', sql.Int, user.departmentId)
        .input('regisNo', sql.VarChar, user.regisNo)
        .input('uName', sql.VarChar, user.name)
        .input('email', sql.VarChar, user.email)
        .input('mobile', sql.VarChar, user.phone)
        .input('password', sql.VarChar, user.password)
        .input('hashPassword', sql.VarChar, hashedPassword)
        .input('address', sql.VarChar, 'Demo Address')
        .input('roleId', sql.Int, user.role)
        .input('isActive', sql.Bit, 1)
        .input('isAvailable', sql.Bit, 1)
        .input('isAccountVerified', sql.Bit, 1)
        .input('createdBy', sql.VarChar, '1')
        .query(`
          INSERT INTO Users (
            Department_Id, Regis_No, U_Name, Email_ID, Mobile_No,
            u_Password, Hash_Password, U_Address, Role_Id,
            IsActive, IsAvailable, IsAccount_Verified, Created_By, Created_at
          ) VALUES (
            @departmentId, @regisNo, @uName, @email, @mobile,
            @password, @hashPassword, @address, @roleId,
            @isActive, @isAvailable, @isAccountVerified, @createdBy, GETDATE()
          )
        `);
    }
    
    console.log('Demo users created successfully');
  } catch (error) {
    console.error('Error creating demo users:', error);
  }
};

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Server Error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start Server
const startServer = async () => {
  try {
    await initializeDatabase();
    await createDemoUsers();
    
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
      console.log(`API Health: http://localhost:${PORT}/api/health`);
      console.log(`Database: ${dbConfig.server}:${dbConfig.port}/${dbConfig.database}`);
      console.log('Demo credentials:');
      console.log('- Admin: username=admin, password=admin');
      console.log('- Employee: username=employee, password=employee');
      console.log('- Manager: username=manager, password=manager');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();