// server.js - Main Backend Server
const express = require('express');
const cors = require('cors');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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
    console.log('✅ Connected to SQL Server Database');
  } catch (error) {
    console.error('❌ Database connection failed:', error);
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
      type = 'user', status = 'Active'
    } = req.body;

    // Validate required fields
    if (!name || !email || !phone || !password || !address) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }

    const pool = await poolPromise;

    // Check if user already exists
    const existingUser = await pool.request()
      .input('email', sql.VarChar, email)
      .input('phone', sql.VarChar, phone)
      .query('SELECT Id FROM Users WHERE Email_ID = @email OR Mobile_No = @phone');

    if (existingUser.recordset.length > 0) {
      return res.status(400).json({ error: 'User with this email or phone already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Calculate distance from office (Delhi coordinates: 28.6139, 77.2090)
    const officeLat = 28.6139;
    const officeLng = 77.2090;
    const userLat = parseFloat(latitude);
    const userLng = parseFloat(longitude);

    let distance = 0;
    if (userLat && userLng) {
      const R = 6371; // Earth's radius in km
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
      .input('uName', sql.VarChar, name)
      .input('email', sql.VarChar, email)
      .input('mobile', sql.VarChar, phone)
      .input('password', sql.VarChar, password)
      .input('hashPassword', sql.VarChar, hashedPassword)
      .input('address', sql.VarChar, address)
      .input('lat', sql.Decimal(10, 8), userLat || null)
      .input('lng', sql.Decimal(11, 8), userLng || null)
      .input('distance', sql.Decimal(10, 2), distance)
      .input('isActive', sql.Bit, status === 'Active' ? 1 : 0)
      .input('roleId', sql.Int, type === 'admin' ? 1 : 2)
      .input('createdBy', sql.Int, 1)
      .query(`
        INSERT INTO Users (
          U_Name, Email_ID, Mobile_No, u_Password, Hash_Password,
          U_Address, Lat_Address, Long_Address, Distance,
          IsActive, Role_Id, Created_By, Created_at
        ) VALUES (
          @uName, @email, @mobile, @password, @hashPassword,
          @address, @lat, @lng, @distance,
          @isActive, @roleId, @createdBy, GETDATE()
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
        name,
        email,
        phone,
        distance: `${distance} km`
      }
    });

  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Get All Users
app.get('/api/users', async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT 
        Id, U_Name, Email_ID, Mobile_No, U_Address,
        Lat_Address, Long_Address, Distance, IsActive,
        Role_Id, Created_at, Last_Login_at
      FROM Users
      ORDER BY Created_at DESC
    `);

    const users = result.recordset.map(user => ({
      id: user.Id,
      name: user.U_Name,
      email: user.Email_ID,
      phone: user.Mobile_No,
      address: user.U_Address,
      latitude: user.Lat_Address,
      longitude: user.Long_Address,
      distance: user.Distance,
      status: user.IsActive ? 'Active' : 'Inactive',
      role: user.Role_Id === 1 ? 'Admin' : 'User',
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

    const result = await pool.request()
      .input('vendorName', sql.VarChar, vendorName)
      .input('vendorPhone', sql.VarChar, vendorPhoneNo)
      .input('vendorEmail', sql.VarChar, vendorEmailId)
      .input('vendorAddress', sql.VarChar, vendorAddress)
      .input('vendorAPI', sql.VarChar, vendorAPI || '')
      .input('isActive', sql.Bit, activeDeactive ? 1 : 0)
      .input('createdBy', sql.Int, 1)
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
      .input('createdBy', sql.Int, 1)
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

    const result = await pool.request()
      .input('driverName', sql.VarChar, driverName)
      .input('driverPhone', sql.VarChar, phone)
      .input('driverAddress', sql.VarChar, address || '')
      .input('emergencyContact', sql.VarChar, emergencyName || '')
      .input('emergencyPhone', sql.VarChar, emergencyPhone || '')
      .input('gender', sql.VarChar, gender || '')
      .input('dob', sql.Date, dob || null)
      .input('experience', sql.Int, parseInt(experience) || 0)
      .input('dlNo', sql.VarChar, licenseNumber)
      .input('dlExpire', sql.Date, expiryDate || null)
      .input('isActive', sql.Bit, 1)
      .input('isAvailable', sql.Bit, 1)
      .input('createdBy', sql.Int, 1)
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

    if (!routeId || !name || !origin || !destination) {
      return res.status(400).json({ error: 'Route ID, name, origin, and destination are required' });
    }

    const pool = await poolPromise;
    const transaction = new sql.Transaction(pool);

    try {
      await transaction.begin();

      // Insert route
      const routeResult = await transaction.request()
        .input('routeNo', sql.VarChar, routeId)
        .input('routeName', sql.VarChar, name)
        .input('routeSource', sql.VarChar, origin)
        .input('routeDestination', sql.VarChar, destination)
        .input('estimatedDistance', sql.Decimal(10, 2), parseFloat(estimatedDistanceKm) || 0)
        .input('estimatedTime', sql.Int, parseInt(estimatedTimeMinutes) || 0)
        .input('isActive', sql.Bit, isActive ? 1 : 0)
        .input('createdBy', sql.Int, 1)
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

      // Insert stops if provided
      if (stops && stops.length > 0) {
        for (let i = 0; i < stops.length; i++) {
          const stop = stops[i];
          
          // First insert the stop
          const stopResult = await transaction.request()
            .input('stopName', sql.VarChar, stop.stopName)
            .input('stopAddress', sql.VarChar, stop.address)
            .input('stopLat', sql.Decimal(10, 8), parseFloat(stop.lat) || null)
            .input('stopLong', sql.Decimal(11, 8), parseFloat(stop.lng) || null)
            .input('isActive', sql.Bit, 1)
            .input('createdBy', sql.Int, 1)
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

          // Then map the stop to the route
          await transaction.request()
            .input('routeId', sql.Int, newRouteId)
            .input('stoppageId', sql.Int, stoppageId)
            .input('isActive', sql.Bit, 1)
            .input('createdBy', sql.Int, 1)
            .query(`
              INSERT INTO Mstmap_Route_Stoppage (
                Route_Id, Stoppage_Id, IsActive, Created_By, Created_at
              ) VALUES (
                @routeId, @stoppageId, @isActive, @createdBy, GETDATE()
              );
            `);
        }
      }

      await transaction.commit();

      res.status(201).json({
        success: true,
        message: 'Route created successfully',
        routeId: newRouteId,
        stopsAdded: stops.length
      });

    } catch (error) {
      await transaction.rollback();
      throw error;
    }

  } catch (error) {
    console.error('Create route error:', error);
    res.status(500).json({ error: 'Failed to create route' });
  }
});

// Get All Routes
app.get('/api/routes', async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT 
        Id, Route_No, Route_Name, Route_Source, Route_Destination,
        Eastimated_Distance, Eastimated_Time, IsActive, Created_at
      FROM Mst_Routes
      ORDER BY Created_at DESC
    `);

    const routes = result.recordset.map(route => ({
      id: route.Id,
      routeNo: route.Route_No,
      name: route.Route_Name,
      source: route.Route_Source,
      destination: route.Route_Destination,
      distance: `${route.Eastimated_Distance} km`,
      duration: `${route.Eastimated_Time} mins`,
      status: route.IsActive ? 'Active' : 'Inactive',
      createdAt: route.Created_at
    }));

    res.json({ success: true, data: routes });
  } catch (error) {
    console.error('Get routes error:', error);
    res.status(500).json({ error: 'Failed to fetch routes' });
  }
});

// ===================== CAB REQUEST ROUTES =====================

// Create Cab Request
app.post('/api/cab-requests', async (req, res) => {
  try {
    const {
      userId = 1, pickupLocation, pickupLat, pickupLng,
      destination, destinationLat, destinationLng,
      requestedDateTime, contactNumber
    } = req.body;

    if (!pickupLocation || !destination || !requestedDateTime) {
      return res.status(400).json({ error: 'Pickup location, destination, and requested time are required' });
    }

    const pool = await poolPromise;

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
      .input('createdBy', sql.Int, userId)
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

// ===================== DASHBOARD ROUTES =====================

// Get Dashboard Stats
app.get('/api/dashboard/stats', async (req, res) => {
  try {
    const pool = await poolPromise;
    
    const [users, vehicles, drivers, routes, requests] = await Promise.all([
      pool.request().query('SELECT COUNT(*) as count FROM Users WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) as count FROM Mst_Vehicle WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) as count FROM Mst_Driver WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) as count FROM Mst_Routes WHERE IsActive = 1'),
      pool.request().query('SELECT COUNT(*) as count FROM Cab_Requests WHERE Status = \'PENDING\'')
    ]);

    res.json({
      success: true,
      data: {
        users: users.recordset[0].count,
        vehicles: vehicles.recordset[0].count,
        drivers: drivers.recordset[0].count,
        routes: routes.recordset[0].count,
        activeRequests: requests.recordset[0].count
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
        CONCAT('New booking from ', u.U_Name, ' to ', cr.Destination) as message,
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
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
      console.log(`📊 API Health: http://localhost:${PORT}/api/health`);
      console.log(`🔗 Database: ${dbConfig.server}:${dbConfig.port}/${dbConfig.database}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();