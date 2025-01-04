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

const allowedOrigins = [
    'http://localhost:3000',
    'https://cdr2.com',
    'https://dharristours.simpsf.com'
];

// Initialize express app
const app = express();
const userManager = new UserManager();
const sessionSecret = crypto.randomBytes(32).toString('hex');

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

// Use the session middleware in Express
app.use(session(sessionConfig));

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
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Origin', origin);
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

// Configure storage for uploaded files
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!req.session.userId) {
            cb(new Error('Not authenticated'));
            return;
        }
        const uploadPath = userManager.getUserUploadPath(req.session.userId);
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const ext = mime.extension(file.mimetype);
        crypto.randomBytes(16, (err, raw) => {
            cb(null, raw.toString('hex') + Date.now() + '.' + ext);
        });
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB limit
    }
});

// SSL/TLS certificate configuration
const certPath = '/etc/letsencrypt/live/11oclocktoast.com';
const credentials = {
    cert: fs.readFileSync(path.join(certPath, 'fullchain.pem')),
    key: fs.readFileSync(path.join(certPath, 'privkey.pem')),
    ca: fs.readFileSync(path.join(certPath, 'chain.pem'))
};

// Create HTTPS server with certificates
const server = https.createServer(credentials, app);

// Create WebSocket server instance
const wss = new WebSocket.Server({ server, 
    verifyClient: (info, callback) => {
        console.log('Verifying client connection...');
        sessionMiddleware(info.req, {}, () => {
            const userId = info.req.session?.userId;
            console.log(`Session userId: ${userId}`);
            callback(true);
        });
    }
});

// Store active connections and their usernames
const clients = new Map();

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
wss.on('connection', (ws, req) => {
    const sessionId = req.session?.userId;
    console.log(`Client connected [${sessionId}]`);

    if (!sessionId) {
        ws.send(JSON.stringify({
            type: 'system',
            content: 'Please log in to join the chat.',
            timestamp: new Date().toISOString()
        }));
        ws.close();
        return;
    }

    try {
        async () => {
            const profile = await userManager.getUserProfile(sessionId);
            clients.set(ws, profile.Login); // Use Login to match client expectations

            ws.send(JSON.stringify({
                type: 'system',
                content: 'Connected to chat server.',
                timestamp: new Date().toISOString()
            }));
        };
    } catch (error) {
        console.error('Error getting user profile:', error);
        ws.close();
    }
    // Handle incoming messages
    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data);

            switch (message.type) {
                case 'join':
                    // Update the client's username
                    clients.set(ws, message.username);

                    // Send recent history to newly joined user
                    const recentHistory = chatHistory.getRecent();
                    ws.send(JSON.stringify({
                        type: 'history',
                        content: recentHistory,
                        timestamp: new Date().toISOString()
                    }));

                    // Broadcast join notification
                    const joinMessage = {
                        type: 'system',
                        content: `${message.username} has joined the chat`,
                        timestamp: new Date().toISOString()
                    };
                    broadcast(joinMessage, ws);
                    chatHistory.add(joinMessage);

                    // Send welcome message
                    ws.send(JSON.stringify({
                        type: 'system',
                        content: `Welcome, ${message.username}! Last ${recentHistory.length} messages have been loaded.`,
                        timestamp: new Date().toISOString()
                    }));

                    broadcastUserList();

                    break;
                case 'status':
                    const statusMessage = {
                        type: 'system',
                        messageType: 'status',
                        username: message.username,
                        content: message.content,
                        timestamp: new Date().toISOString()
                    };

                    broadcast(statusMessage, ws);

                    break;
                case 'users':
                     ws.send(JSON.stringify({
                        type: 'users',
                        content: getOnlineUsers(),
                        timestamp: new Date().toISOString()
                    }));
                    break;
                case 'chat':
                    const username = clients.get(ws);
                    if (!username) {
                        ws.send(JSON.stringify({
                            type: 'system',
                            content: 'Please identify yourself before sending messages.',
                            timestamp: new Date().toISOString()
                        }));
                        return;
                    }

                    const chatMessage = {
                        type: 'chat',
                        messageType: message.messageType || 'text',
                        username: username,
                        content: message.content,
                        timestamp: new Date().toISOString()
                    };

                    // For images, validate base64 data
                    if (message.messageType === 'image') {
                        if (!message.content.startsWith('data:image/')) {
                            ws.send(JSON.stringify({
                                type: 'system',
                                content: 'Invalid image data',
                                timestamp: new Date().toISOString()
                            }));
                            return;
                        }
                        // Optionally implement size limits here
                        const base64Size = message.content.length * 0.75; // Approximate size in bytes
                        if (base64Size > 5 * 1024 * 1024) { // 5MB limit
                            ws.send(JSON.stringify({
                                type: 'system',
                                content: 'Image too large (max 5MB)',
                                timestamp: new Date().toISOString()
                            }));
                            return;
                        }
                    }

                    // Broadcast and log message
                    broadcast(chatMessage, ws);
                    ws.send(JSON.stringify(chatMessage)); // Send to sender
                    chatHistory.add(chatMessage);
                    break;
            }
        } catch (error) {
            console.error('Error processing message:', error);
            ws.send(JSON.stringify({
                type: 'system',
                content: 'Error processing message',
                timestamp: new Date().toISOString()
            }));
        }
    });

    // Handle client disconnection
    ws.on('close', () => {
        const username = clients.get(ws);
        if (username) {
            const leaveMessage = {
                type: 'system',
                content: `${username} has left the chat`,
                timestamp: new Date().toISOString()
            };
            broadcast(leaveMessage);
            chatHistory.add(leaveMessage);

            // Broadcast updated user list after disconnection
            clients.delete(ws);
            broadcastUserList();
        } else {
            clients.delete(ws);
        }
        console.log('Client disconnected');
    });

    // Handle errors
    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        if (clients.has(ws)) {
            clients.delete(ws);
            broadcastUserList();
        }
    });
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
        // Your existing login handler code
        try {
            const { username, password } = req.body;
            const isValid = await userManager.validateUser(username, password);

            if (!isValid) {
                return sendResponse(res, 401, 'Invalid credentials');
            }

            const profile = await userManager.getUserProfile(username);
            req.session.userId = profile.id;
            req.session.username = username;

            return sendResponse(res, 200, 'Login successful', { profile });
        } catch (error) {
            return sendResponse(res, 500, 'Login failed', null, error);
        }
    });

app.get('/api/profile', async (req, res) => {
    if (!req.session.userId) {
        return sendResponse(res, 401, 'Not authenticated');
    }

    try {
        const profile = await userManager.getUserProfile(req.session.userId);
        return sendResponse(res, 200, 'Profile retrieved successfully', { profile });
    } catch (error) {
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

app.post('/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Return file information
        return sendResponse(res, 200, 'File uploaded successfully', {
            filename: req.file.filename,
            mimetype: req.file.mimetype,
            size: req.file.size,
            url: `/uploads/${req.file.filename}`
        });
    } catch (error) {
        console.error('Upload error:', error);
        return sendResponse(res, 500, 'Upload failed', null, error);
    }
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
