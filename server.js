// server.js - Cyber Chitty Backend Server
// Developed by 🪙BTC ©️CYBERLORD👑

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key-change-this-in-production';

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Initialize SQLite Database
const db = new sqlite3.Database('./cyber_chitty.db');

// Create tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        password_hash TEXT,
        verification_code TEXT,
        is_verified BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Messages table
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        message_type TEXT DEFAULT 'message',
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Sessions table for active users
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        socket_id TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
});

// Connected users tracking
const connectedUsers = new Map();

// Utility Functions
function generateVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function validatePhoneNumber(phone) {
    const phoneRegex = /^\+?[\d\s\-\(\)]{10,15}$/;
    return phoneRegex.test(phone);
}

// Routes

// User Registration/Login
app.post('/api/auth/register', async (req, res) => {
    const { phone, name } = req.body;

    if (!validatePhoneNumber(phone) || !name || name.trim().length < 1) {
        return res.status(400).json({ error: 'Invalid phone number or name' });
    }

    const cleanPhone = phone.replace(/\D/g, '');
    const verificationCode = generateVerificationCode();

    try {
        // Check if user exists
        db.get('SELECT * FROM users WHERE phone = ?', [cleanPhone], (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            if (user) {
                // User exists, update verification code
                db.run('UPDATE users SET verification_code = ?, name = ? WHERE phone = ?', 
                    [verificationCode, name.trim(), cleanPhone], (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Database error' });
                    }
                    
                    // In production, send SMS here
                    console.log(`Verification code for ${cleanPhone}: ${verificationCode}`);
                    
                    res.json({ 
                        success: true, 
                        message: 'Verification code sent',
                        userId: user.id,
                        // In production, don't send the code in response
                        verificationCode: verificationCode 
                    });
                });
            } else {
                // Create new user
                db.run('INSERT INTO users (phone, name, verification_code) VALUES (?, ?, ?)', 
                    [cleanPhone, name.trim(), verificationCode], function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Database error' });
                    }
                    
                    // In production, send SMS here
                    console.log(`Verification code for ${cleanPhone}: ${verificationCode}`);
                    
                    res.json({ 
                        success: true, 
                        message: 'Verification code sent',
                        userId: this.lastID,
                        // In production, don't send the code in response
                        verificationCode: verificationCode 
                    });
                });
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify phone number
app.post('/api/auth/verify', (req, res) => {
    const { userId, verificationCode } = req.body;

    db.get('SELECT * FROM users WHERE id = ? AND verification_code = ?', 
        [userId, verificationCode], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(400).json({ error: 'Invalid verification code' });
        }

        // Mark user as verified
        db.run('UPDATE users SET is_verified = 1, verification_code = NULL WHERE id = ?', 
            [userId], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            // Generate JWT token
            const token = jwt.sign(
                { userId: user.id, phone: user.phone, name: user.name },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                success: true,
                token: token,
                user: {
                    id: user.id,
                    phone: user.phone,
                    name: user.name
                }
            });
        });
    });
});

// Get chat messages
app.get('/api/messages', authenticateToken, (req, res) => {
    const limit = req.query.limit || 50;
    
    db.all(`SELECT m.*, u.name as user_name 
            FROM messages m 
            JOIN users u ON m.user_id = u.id 
            ORDER BY m.timestamp DESC 
            LIMIT ?`, [limit], (err, messages) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({ messages: messages.reverse() });
    });
});

// Get online users
app.get('/api/users/online', authenticateToken, (req, res) => {
    const onlineUserIds = Array.from(connectedUsers.keys());
    
    if (onlineUserIds.length === 0) {
        return res.json({ users: [] });
    }
    
    const placeholders = onlineUserIds.map(() => '?').join(',');
    db.all(`SELECT id, name, phone FROM users WHERE id IN (${placeholders})`, 
        onlineUserIds, (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({ users });
    });
});

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Socket.IO Connection Handling
io.on('connection', (socket) => {
    console.log('New connection:', socket.id);

    // User joins
    socket.on('join', (userData) => {
        try {
            const decoded = jwt.verify(userData.token, JWT_SECRET);
            
            connectedUsers.set(decoded.userId, {
                socketId: socket.id,
                ...decoded
            });

            socket.userId = decoded.userId;
            socket.join('main_room');

            // Update user's last seen
            db.run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [decoded.userId]);

            // Broadcast user joined
            socket.broadcast.to('main_room').emit('user_joined', {
                userId: decoded.userId,
                name: decoded.name
            });

            // Send current online users
            const onlineUsers = Array.from(connectedUsers.values()).map(u => ({
                userId: u.userId,
                name: u.name
            }));
            
            io.to('main_room').emit('online_users', onlineUsers);

            console.log(`User ${decoded.name} joined the chat`);
        } catch (error) {
            socket.emit('auth_error', { error: 'Invalid token' });
        }
    });

    // Handle new messages
    socket.on('send_message', (data) => {
        if (!socket.userId) return;

        const user = connectedUsers.get(socket.userId);
        if (!user) return;

        const messageContent = data.content.trim();
        if (!messageContent || messageContent.length > 500) return;

        // Save message to database
        db.run('INSERT INTO messages (user_id, content) VALUES (?, ?)', 
            [user.userId, messageContent], function(err) {
            if (err) {
                console.error('Error saving message:', err);
                return;
            }

            const message = {
                id: this.lastID,
                userId: user.userId,
                userName: user.name,
                content: messageContent,
                timestamp: new Date().toISOString(),
                type: 'message'
            };

            // Broadcast message to all users in the room
            io.to('main_room').emit('new_message', message);
            
            console.log(`Message from ${user.name}: ${messageContent}`);
        });
    });

    // Handle typing indicators
    socket.on('typing_start', () => {
        if (!socket.userId) return;
        const user = connectedUsers.get(socket.userId);
        if (user) {
            socket.broadcast.to('main_room').emit('user_typing', {
                userId: user.userId,
                name: user.name
            });
        }
    });

    socket.on('typing_stop', () => {
        if (!socket.userId) return;
        const user = connectedUsers.get(socket.userId);
        if (user) {
            socket.broadcast.to('main_room').emit('user_stopped_typing', {
                userId: user.userId
            });
        }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        if (socket.userId) {
            const user = connectedUsers.get(socket.userId);
            if (user) {
                connectedUsers.delete(socket.userId);
                
                // Update last seen in database
                db.run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [socket.userId]);
                
                // Broadcast user left
                socket.broadcast.to('main_room').emit('user_left', {
                    userId: socket.userId,
                    name: user.name
                });

                // Send updated online users list
                const onlineUsers = Array.from(connectedUsers.values()).map(u => ({
                    userId: u.userId,
                    name: u.name
                }));
                
                io.to('main_room').emit('online_users', onlineUsers);

                console.log(`User ${user.name} left the chat`);
            }
        }
    });
});

// Serve the main HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        connectedUsers: connectedUsers.size 
    });
});

// Get user statistics
app.get('/api/stats', authenticateToken, (req, res) => {
    db.get('SELECT COUNT(*) as total_users FROM users WHERE is_verified = 1', (err, userCount) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        db.get('SELECT COUNT(*) as total_messages FROM messages', (err, messageCount) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            res.json({
                totalUsers: userCount.total_users,
                totalMessages: messageCount.total_messages,
                onlineUsers: connectedUsers.size
            });
        });
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
server.listen(PORT, () => {
    console.log(`🚀 Cyber Chitty server is running on port ${PORT}`);
    console.log(`📱 Access your app at: http://localhost:${PORT}`);
    console.log(`💾 Database: ${path.join(__dirname, 'cyber_chitty.db')}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n📴 Shutting down Cyber Chitty server...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('💾 Database connection closed.');
        }
        process.exit(0);
    });
});
