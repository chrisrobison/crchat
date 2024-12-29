const WebSocket = require('ws');
const https = require('https');
const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const mime = require('mime-types');
const crypto = require('crypto');
const UserManager = require('./user-manager');
const bodyParser = require('body-parser');
const session = require('express-session');

// Initialize express app
const app = express();

// Initialize user manager
app.use(bodyParser.json());
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true,
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    }
}));

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
const wss = new WebSocket.Server({ server });

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
    console.log('Client connected');
    const sessionId = req.session?.userId;
    
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
        const profile = await userManager.getUserProfile(sessionId);
        clients.set(ws, profile.Login); // Use Login to match client expectations
        
        ws.send(JSON.stringify({
            type: 'system',
            content: 'Connected to chat server.',
            timestamp: new Date().toISOString()
        }));

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
    res.status(200).json({
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
        const userData = {
            username: req.body.username,
            password: req.body.password,
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            location: req.body.location,
            phone: req.body.phone
        };

        const user = await userManager.createUser(userData);
        res.json({
            status: 'success',
            user: user
        });
    } catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const isValid = await userManager.validateUser(username, password);
        
        if (!isValid) {
            res.status(401).json({
                status: 'error',
                message: 'Invalid credentials'
            });
            return;
        }

        const profile = await userManager.getUserProfile(username);
        req.session.userId = profile.id;
        req.session.username = username;

        res.json({
            status: 'success',
            profile: profile
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: error.message
        });
    }
});

app.get('/api/profile', async (req, res) => {
    if (!req.session.userId) {
        res.status(401).json({
            status: 'error',
            message: 'Not authenticated'
        });
        return;
    }

    try {
        const profile = await userManager.getUserProfile(req.session.userId);
        res.json({
            status: 'success',
            profile: profile
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: error.message
        });
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
        res.json({
            status: 'success',
            profile: updatedProfile
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: error.message
        });
    }
});

app.post('/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Return file information
        res.json({
            filename: req.file.filename,
            mimetype: req.file.mimetype,
            size: req.file.size,
            url: `/uploads/${req.file.filename}`
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// Endpoint to get other users' profiles
app.get('/api/userprofile', async (req, res) => {
    try {
        const username = req.query.user;
        if (!username) {
            return res.status(400).json({
                status: 'error',
                message: 'Username is required'
            });
        }

        const profile = await userManager.getUserProfile(username);
        
        // Return in format matching existing client expectations
        res.json({
            status: 'success',
            ...profile  // This spreads Login, Picture, and other profile fields
        });
    } catch (error) {
        res.status(404).json({
            status: 'error',
            message: 'User not found'
        });
    }
});


// Serve uploaded files
app.use('/uploads', express.static('uploads'));

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
