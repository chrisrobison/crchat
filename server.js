const WebSocket = require('ws');
const https = require('https');
const express = require('express');
const fs = require('fs');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const mime = require('mime-types');
const crypto = require('crypto');
const UserManager = require('./user-manager');
const bodyParser = require('body-parser');
const session = require('express-session');
const jwt = require('jsonwebtoken');

const allowedOrigins = [
    'http://localhost:3000',
    'https://cdr2.com',
    'https://dharristours.simpsf.com'
];

// Initialize express app
const app = express();
const userManager = new UserManager();

// JWT setup
// Load or generate a persistent JWT secret
const JWT_SECRET_FILE = path.join(__dirname, '.jwt-secret');
let JWT_SECRET;

try {
    // Try to load existing secret
    if (fs.existsSync(JWT_SECRET_FILE)) {
        JWT_SECRET = fs.readFileSync(JWT_SECRET_FILE, 'utf8');
        console.log('Loaded existing JWT secret');
    } else {
        // Generate and save new secret if none exists
        JWT_SECRET = crypto.randomBytes(64).toString('hex');
        fs.writeFileSync(JWT_SECRET_FILE, JWT_SECRET);
        console.log('Generated and saved new JWT secret');
    }
} catch (error) {
    console.error('Error handling JWT secret:', error);
    process.exit(1);
}

// Use existing session secret or generate new one
const sessionSecret = crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY = '30d'; // 30 days

// Create session middleware
const sessionConfig = {
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    name: 'sessionId',  // Custom name for clarity
    rolling: true,      // Reset expiration on every response
    cookie: {
        secure: true,   // For HTTPS
        httpOnly: true, // Prevent XSS
        sameSite: 'none', // For cross-origin
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days in milliseconds
    }
};

// Create the session middleware and save for later
const sessionMiddleware = session(sessionConfig);

// Use the session middleware in Express
app.use(sessionMiddleware);

app.use(express.json());
app.use(bodyParser.json());

app.options('*', (req, res) => {
    const origin = req.headers.origin;
    
    // Check if the origin is allowed
    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Headers', [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
            'Accept',
            'Origin',
            'Access-Control-Allow-Headers',
            'Access-Control-Request-Headers',
            'Access-Control-Allow-Origin'
        ].join(', '));
        res.setHeader('Access-Control-Expose-Headers', 'Set-Cookie');
    }
    
    // Send 204 No Content
    res.status(204).end();
});

// Initialize user manager when starting the server
(async () => {
    try {
        await userManager.initialize();
        console.log('User management system initialized');
    } catch (error) {
        console.error('Failed to initialize user management:', error);
        process.exit(1);
    }
})();

// Authentication middleware
const verifyToken = async (req, res, next) => {
    try {
        // Try getting token from cookies first
        let token = req.cookies?.auth_token;

        // Fallback to Authorization header
        if (!token && req.headers.authorization) {
            token = req.headers.authorization.replace('Bearer ', '');
        }

        if (!token) {
            console.log('No token found in request');
            return sendResponse(res, 401, 'Authentication required');
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            console.log('Token verified for user:', decoded.username);
            
            // Store the decoded user info in the request
            req.user = decoded;
            next();
        } catch (error) {
            console.log('Token verification failed:', error.message);
            return sendResponse(res, 401, 'Invalid token');
        }
    } catch (error) {
        console.error('Auth middleware error:', error);
        return sendResponse(res, 500, 'Internal server error');
    }
};

/**
 * Centralized response handler for consistent response formatting and CORS headers
 * @param {Object} res - Express response object
 * @param {number} status - HTTP status code
 * @param {string} message - Response message
 * @param {Object|Array} [data] - Optional data payload
 * @param {Error} [error] - Optional error object
 */
function sendResponse(res, status, message, data = null, error = null) {
    // Get the origin from the request
    const origin = res.req.headers.origin;

    // Set CORS headers if origin is allowed
    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
            'Accept',
            'Origin',
            'Access-Control-Allow-Headers',
            'Access-Control-Request-Headers',
            'Access-Control-Allow-Origin'
        ].join(', '));
        res.setHeader('Access-Control-Expose-Headers', 'Set-Cookie');
    }

    // Construct the response object
    const response = {
        status: status < 400 ? 'success' : 'error',
        message,
        timestamp: new Date().toISOString()
    };

    // Add data if provided
    if (data) {
        response.data = data;
    }

    // Add error details if provided and it's an error response
    if (error && status >= 400) {
        response.error = {
            message: error.message,
            ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
        };
    }

    // Send the response
    return res.status(status).json(response);
}

// Helper function to get token from request
const getTokenFromRequest = (req) => {
    // Check for token in cookies if cookies exist
    if (req.cookies && req.cookies.auth_token) {
        return req.cookies.auth_token;
    }
    
    // Check Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7); // Remove 'Bearer ' prefix
    }
    
    return null;
};

// Configure storage for uploaded files
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        try {
            // Get token using helper function
            const token = getTokenFromRequest(req);
            
            if (!token) {
                console.log('No token found in request');
                cb(new Error('Not authenticated'));
                return;
            }

            try {
                // Verify the token
                const decoded = jwt.verify(token, JWT_SECRET);
                console.log('Upload request from user:', decoded.username);

                // Get user upload path
                const uploadPath = path.join(__dirname, 'uploads', decoded.userId);
                
                // Create directory if it doesn't exist
                fs.mkdirSync(uploadPath, { recursive: true });
                
                console.log('Upload path created:', uploadPath);
                cb(null, uploadPath);
            } catch (error) {
                console.error('Token verification failed:', error);
                cb(new Error('Invalid authentication token'));
            }
        } catch (error) {
            console.error('Upload error:', error);
            cb(error);
        }
    },
    filename: (req, file, cb) => {
        const ext = mime.extension(file.mimetype) || 'unknown';
        crypto.randomBytes(16, (err, raw) => {
            if (err) {
                cb(err);
                return;
            }
            const filename = raw.toString('hex') + Date.now() + '.' + ext;
            console.log('Generated filename:', filename);
            cb(null, filename);
        });
    }
});

// Create multer upload middleware with error handling
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB limit
    },
    fileFilter: (req, file, cb) => {
        // Validate file types
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'video/mp4'];
        if (!allowedTypes.includes(file.mimetype)) {
            cb(new Error('Invalid file type'), false);
            return;
        }
        cb(null, true);
    }
}).single('file');

// Wrap multer middleware to handle errors properly
const uploadMiddleware = (req, res, next) => {
    upload(req, res, (err) => {
        if (err) {
            console.error('Upload middleware error:', err);
            return sendResponse(res, 400, err.message);
        }
        next();
    });
};


// SSL/TLS certificate configuration
const certPath = '/etc/letsencrypt/live/11oclocktoast.com';
const credentials = {
    cert: fs.readFileSync(path.join(certPath, 'fullchain.pem')),
    key: fs.readFileSync(path.join(certPath, 'privkey.pem')),
    ca: fs.readFileSync(path.join(certPath, 'chain.pem'))
};

// Create HTTPS server with certificates
const server = https.createServer(credentials, app);

// WebSocket server with detailed authentication logging
const wss = new WebSocket.Server({ 
    server,
    verifyClient: async (info, callback) => {
        console.log('WebSocket connection attempt...');
        
        try {
            // Try getting token from cookies first
            let token = null;
            if (info.req.headers.cookie) {
                const cookies = parseCookies(info.req.headers.cookie);
                token = cookies.auth_token;
            }

            // Fallback to Authorization header if no cookie
            if (!token && info.req.headers.authorization) {
                token = info.req.headers.authorization.replace('Bearer ', '');
            }

            if (!token) {
                console.log('No authentication token found');
                callback(false, 401, 'No authentication token found');
                return;
            }

            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                console.log('Token verified successfully:', decoded);
                
                // Store user info in the request object
                info.req.user = decoded;
                
                // This is crucial - we're storing the verified user data
                info.req.verifiedUser = {
                    userId: decoded.userId,
                    username: decoded.username
                };
                
                callback(true);
            } catch (error) {
                console.log('Token verification failed:', error.message);
                callback(false, 401, 'Invalid token');
            }
        } catch (error) {
            console.error('WebSocket authentication error:', error);
            callback(false, 401, 'Authentication failed');
        }
    }
});

// Store active connections and their usernames
const clients = new Map();

// Helper function to parse cookies
function parseCookies(cookieHeader) {
    const cookies = {};
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const [name, value] = cookie.split('=').map(c => c.trim());
            cookies[name] = value;
        });
    }
    return cookies;
}

// Function to get list of online users
function getOnlineUsers() {
    const users = [];
    clients.forEach((username, client) => {
        if (username && client.readyState === WebSocket.OPEN) {
            users.push(username);
        }
    });
    return users.sort();  // Sort alphabetically for consistency
}

// Function to broadcast user list to all clients
function broadcastUserList() {
    const userList = {
        type: 'users',
        content: getOnlineUsers(),
        timestamp: new Date().toISOString()
    };
    const messageString = JSON.stringify(userList);
    clients.forEach((username, client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(messageString);
        }
    });
}

// Chat history management
const chatHistory = {
    filename: '/home/cdr/cdr2/crchat/chat_history.jsonl',
    maxMessages: 1000, // Keep last 1000 messages
    messages: [],

    init() {
        try {
            if (fs.existsSync(this.filename)) {
                const content = fs.readFileSync(this.filename, 'utf8');
                this.messages = content
                    .split('\n')
                    .filter(line => line.trim())
                    .map(line => JSON.parse(line))
                    .slice(-this.maxMessages);
                console.log(`Loaded ${this.messages.length} messages from history`);
            }
        } catch (error) {
            console.error('Error loading chat history:', error);
            this.messages = [];
        }
    },

    add(message) {
        // Don't log certain system messages
        if (message.type === 'system' &&
            (message.content.includes('Connected to chat server') ||
             message.content.includes('Please identify yourself'))) {
            return;
        }

        this.messages.push(message);
        if (this.messages.length > this.maxMessages) {
            this.messages = this.messages.slice(-this.maxMessages);
        }

        // Append to file
        try {
            fs.appendFileSync(this.filename, JSON.stringify(message) + '\n');
        } catch (error) {
            console.error('Error saving message to history:', error);
        }
    },

    getRecent(count = 100) {
        return this.messages.slice(-count);
    }
};

// Initialize chat history
chatHistory.init();

// Broadcast message to all connected clients except sender
function broadcast(message, sender) {
    const messageString = JSON.stringify(message);
    clients.forEach((username, client) => {
        if (client !== sender && client.readyState === WebSocket.OPEN) {
            client.send(messageString);
        }
    });
}

// Handle new WebSocket connections
wss.on('connection', async (ws, req) => {
    const user = req.verifiedUser;
    console.log('Client connected:', user);

    if (!user || !user.username) {
        console.error('No user information available');
        ws.close(1008, 'No user information');
        return;
    }

    try {
        // Add to clients map with verified username
        clients.set(ws, user.username);
        
        console.log('Sending welcome message to:', user.username);
        ws.send(JSON.stringify({
            type: 'system',
            content: 'Connected to chat server.',
            timestamp: new Date().toISOString()
        }));

        // Load and send recent history
        console.log('Loading recent history for:', user.username);
        const recentHistory = chatHistory.getRecent();
        console.log('Recent history count:', recentHistory.length);
        
        ws.send(JSON.stringify({
            type: 'history',
            content: recentHistory,
            timestamp: new Date().toISOString()
        }));

        // Broadcast updated user list
        broadcastUserList();

        // Message handler
        ws.on('message', (data) => {
            console.log('Raw message received:', data.toString());
            
            try {
                const message = JSON.parse(data);
                console.log('Parsed message:', message);
                
                // Always use the verified username
                message.username = user.username;
                
                switch(message.type) {
                    case 'chat':
                        console.log('Processing chat message from:', user.username);
                        const chatMessage = {
                            type: 'chat',
                            username: user.username,
                            content: message.content,
                            timestamp: new Date().toISOString()
                        };
                        console.log('Broadcasting message:', chatMessage);
                        broadcast(chatMessage, ws);
                        ws.send(JSON.stringify(chatMessage));
                        chatHistory.add(chatMessage);
                        break;
                        
                    case 'status':
                        console.log('Processing status message from:', user.username);
                        const statusMessage = {
                            type: 'system',
                            messageType: 'status',
                            username: user.username,
                            content: message.content,
                            timestamp: new Date().toISOString()
                        };
                        broadcast(statusMessage, ws);
                        break;
                        
                    default:
                        console.log('Unknown message type:', message.type);
                }
            } catch (error) {
                console.error('Error processing message:', error);
            }
        });

        // Handle disconnection
        ws.on('close', () => {
            console.log(`Client disconnected: ${user.username}`);
            clients.delete(ws);
            broadcastUserList();
        });

    } catch (error) {
        console.error('Error in connection handler:', error);
        ws.close(1011, 'Internal Server Error');
    }
});

// Periodic cleanup of dead connections
setInterval(() => {
    clients.forEach((username, client) => {
        if (client.readyState === WebSocket.CLOSED) {
            clients.delete(client);
        }
    });
}, 30000);

// API endpoints for chat history
app.get('/api/chat/history', (req, res) => {
    const count = parseInt(req.query.count) || 100;
    res.json(chatHistory.getRecent(count));
});

// Basic health check endpoint
app.get('/health', (req, res) => {
    return sendResponse(res, 200, 'Health check successful', {
        status: 'healthy',
        connections: clients.size,
        secure: true,
        messageCount: chatHistory.messages.length
    });
});

app.get('/users', (req, res) => {
    res.status(200).json(app.getOnlineUsers());
});

app.post('/api/register', async (req, res) => {
    try {
        console.log('Register attempt - received data:', req.body);  // Debug log
        
        // Check if we have all required fields
        const requiredFields = ['username', 'password', 'email'];
        const missingFields = requiredFields.filter(field => !req.body[field]);
        
        if (missingFields.length > 0) {
            console.log('Missing required fields:', missingFields);  // Debug log
            return sendResponse(res, 400, 'Missing required fields', null, {status: 'error', message: `Missing required fields: ${missingFields.join(', ')}`});
        }

        const userData = {
            username: req.body.username,
            password: req.body.password,
            email: req.body.email,
            firstName: req.body.firstName || '',
            lastName: req.body.lastName || '',
            location: req.body.location || '',
            phone: req.body.phone || ''
        };

        console.log('Attempting to create user with data:', {
            ...userData,
            password: '[REDACTED]'  // Don't log the actual password
        });

        const user = await userManager.createUser(userData);
        console.log('User created successfully:', user.username);  // Debug log
        
        return sendResponse(res, 201, 'User registered successfully', {
            user: {
                ...user,
                password: undefined
            }
        });
    } catch (error) {
        return sendResponse(res, 400, 'Registration failed', null, error);
    }
});

app.route('/api/login')
    .options((req, res) => {
        const origin = req.headers.origin;
        if (origin && allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Credentials', 'true');
            res.setHeader('Access-Control-Allow-Headers', [
                'Content-Type',
                'Authorization',
                'X-Requested-With',
                'Accept',
                'Origin',
                'Access-Control-Allow-Headers',
                'Access-Control-Request-Headers',
                'Access-Control-Allow-Origin'
            ].join(', '));
            res.setHeader('Access-Control-Expose-Headers', 'Set-Cookie');
        }
        res.status(204).end();
    })
    .post(async (req, res) => {
        try {
            const { username, password } = req.body;
            const isValid = await userManager.validateUser(username, password);

            if (!isValid) {
                return sendResponse(res, 401, 'Invalid credentials');
            }

            const profile = await userManager.getUserProfile(username);
            // Generate JWT token
            const token = jwt.sign(
                { 
                    userId: profile.id,
                    username: username
                },
                JWT_SECRET,
                { expiresIn: '30d' }
            );

            // Set cookie with proper options
            res.cookie('auth_token', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'none',
                path: '/',
                maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
            });

            console.log('Login successful for user:', username);
            return sendResponse(res, 200, 'Login successful', { 
                profile,
                token
            });
        } catch (error) {
            console.error('Login error:', error);
            return sendResponse(res, 500, 'Login failed', null, error);
        }
    });

app.get('/api/profile', verifyToken, async (req, res) => {
    try {
        console.log('Profile request for user:', req.user.username);
        const profile = await userManager.getUserProfile(req.user.username);
        
        if (!profile) {
            return sendResponse(res, 404, 'Profile not found');
        }

        return sendResponse(res, 200, 'Profile retrieved successfully', { profile });
    } catch (error) {
        console.error('Profile retrieval error:', error);
        return sendResponse(res, 500, 'Failed to retrieve profile', null, error);
    }
});

app.put('/api/profile', async (req, res) => {
    if (!req.session.userId) {
        res.status(401).json({
            status: 'error',
            message: 'Not authenticated'
        });
        return;
    }

    try {
        const updatedProfile = await userManager.updateUserProfile(req.session.userId, req.body);
        return sendResponse(res, 200, 'Profile updated successfully', { updatedProfile });
    } catch (error) {
        return sendResponse(res, 500, 'Failed to update profile', null, error);
    }
});

// Handle preflight request for uploads
app.options('/api/upload', (req, res) => {
    const origin = req.headers.origin;
    
    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
            'Accept',
            'Origin',
            'Access-Control-Allow-Headers',
            'Access-Control-Request-Headers',
            'Access-Control-Allow-Origin'
        ].join(', '));
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Expose-Headers', 'Set-Cookie');
    }
    
    res.status(204).end();
});

// Update the upload endpoint with CORS support
app.post('/api/upload', uploadMiddleware, (req, res) => {
    // Set CORS headers
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    try {
        if (!req.file) {
            return sendResponse(res, 400, 'No file uploaded');
        }

        const fileUrl = `/uploads/${path.basename(req.file.path)}`;
        console.log(`Saving to ${fileUrl}`);
        return sendResponse(res, 200, 'File uploaded successfully', {
            filename: req.file.filename,
            mimetype: req.file.mimetype,
            size: req.file.size,
            url: fileUrl
        });
    } catch (error) {
        console.error('Upload handling error:', error);
        return sendResponse(res, 500, 'Upload failed', null, error);
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('auth_token');
    return sendResponse(res, 200, 'Logged out successfully');
});


// Endpoint to get other users' profiles
app.get('/api/userprofile', async (req, res) => {
    try {
        const username = req.query.user;
        if (!username || username === "undefined") {
            return sendResponse(res, 400, 'Username is required', null, { status: 'error', message: 'Username is required' });
        }

        const profile = await userManager.getUserProfile(username);

        // Return in format matching existing client expectations
        return sendResponse(res, 200, `Successfully retrieved userprofile [${username}] `, {
            status: 'success',
            ...profile  
        });
    } catch (error) {
        return sendResponse(res, 404, 'User not found', null, error);
    }
});


// Serve uploaded files
app.use('/uploads', express.static('uploads'));

app.use((req, res) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.status(404).json({
        status: 'error',
        message: 'Route not found'
    });
});

// Error handling for certificate reading
process.on('uncaughtException', (error) => {
    if (error.code === 'EACCES') {
        console.error('Permission denied when accessing certificate files. Make sure you have the right permissions.');
    } else if (error.code === 'ENOENT') {
        console.error('Certificate files not found. Please check the path:', certPath);
    } else {
        console.error('Uncaught Exception:', error);
    }
    process.exit(1);
});

// Start the secure server
const PORT = process.env.PORT || 3210;
server.listen(PORT, () => {
    console.log(`Secure server is running on port ${PORT}`);
});
