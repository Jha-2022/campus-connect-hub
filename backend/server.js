const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(cors());
app.use(express.json());

// Database Setup
const dbPath = path.resolve(__dirname, 'campus_hub.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Create Events Table
        db.run(`CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            date DATETIME NOT NULL,
            location TEXT,
            organizer_id INTEGER,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(organizer_id) REFERENCES users(id)
        )`);

        // Create Users Table
        db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'student',
      department TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, async (err) => {
            if (err) {
                console.error('Error creating table', err.message);
            } else {
                // Seed Super Admin
                const checkAdminSql = `SELECT * FROM users WHERE email = ?`;
                db.get(checkAdminSql, ['superadmin@campushub.edu'], async (err, row) => {
                    if (!row) {
                        const hashedPassword = await bcrypt.hash('adminmasterkey', 10);
                        const insertAdminSql = `INSERT INTO users (name, email, password, role, department) VALUES (?, ?, ?, ?, ?)`;
                        db.run(insertAdminSql, ['Super Admin', 'superadmin@campushub.edu', hashedPassword, 'admin', 'Administration'], (err) => {
                            if (err) console.error('Error seeding admin', err);
                            else console.log('Super Admin account created.');
                        });
                    }
                });
            }
        });
    }
});

// Routes
// Sign Up
app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password, department } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Please provide name, email, and password.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = `INSERT INTO users (name, email, password, department) VALUES (?, ?, ?, ?)`;
        db.run(sql, [name, email, hashedPassword, department || 'General'], function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ message: 'Email already exists.' });
                }
                return res.status(500).json({ message: 'Database error: ' + err.message });
            }

            const token = jwt.sign({ id: this.lastID, email, name, role: 'student' }, JWT_SECRET, { expiresIn: '24h' });
            res.status(201).json({
                message: 'User registered successfully.',
                token,
                user: { id: this.lastID, name, email, role: 'student', department }
            });
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error.' });
    }
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Please provide email and password.' });
    }

    const sql = `SELECT * FROM users WHERE email = ?`;
    db.get(sql, [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Database error.' });
        }
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({
            message: 'Login successful.',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role, department: user.department }
        });
    });
});

// --- ADMIN ROUTES ---

// Middleware to check if user is admin
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const verifyAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ message: 'Access denied. Admin only.' });
    }
};

// Get All Users
app.get('/api/admin/users', authenticateToken, verifyAdmin, (req, res) => {
    const sql = `SELECT id, name, email, role, department, created_at FROM users`;
    db.all(sql, [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// Update User Role
app.put('/api/admin/users/:id/role', authenticateToken, verifyAdmin, (req, res) => {
    const { role } = req.body;
    const { id } = req.params;

    if (!['admin', 'organizer', 'student'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role.' });
    }

    // Prevent removing own admin status (safety check)
    if (parseInt(id) === req.user.id && role !== 'admin') {
        return res.status(400).json({ message: 'You cannot remove your own admin status.' });
    }

    const sql = `UPDATE users SET role = ? WHERE id = ?`;
    db.run(sql, [role, id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'User role updated successfully', changes: this.changes });
    });
});

// Admin Stats
app.get('/api/admin/stats', authenticateToken, verifyAdmin, (req, res) => {
    // Perform multiple queries to get stats
    const usersCountSql = `SELECT count(*) as count FROM users`;
    // Mocking other stats since we lack tables
    db.get(usersCountSql, [], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });

        const stats = {
            totalUsers: row.count,
            pendingApprovals: 5, // Mock
            activeEvents: 3,     // Mock
            resourceBookings: 8  // Mock
        };
        res.json(stats);
    });
});


// --- EVENTS ROUTES ---

// Create Event
app.post('/api/events', authenticateToken, (req, res) => {
    console.log('Received Create Event Request:', req.body);
    console.log('User:', req.user);
    const { title, description, date, location } = req.body;
    const organizer_id = req.user.id;

    if (!title || !date) {
        return res.status(400).json({ message: 'Title and Date are required.' });
    }

    // Default status is 'pending'
    const sql = `INSERT INTO events (title, description, date, location, organizer_id, status) VALUES (?, ?, ?, ?, ?, 'pending')`;
    db.run(sql, [title, description, date, location, organizer_id], function (err) {
        if (err) {
            console.error('Database Insert Error:', err.message);
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({
            message: 'Event submitted for approval',
            eventId: this.lastID,
            event: { id: this.lastID, title, description, date, location, status: 'pending' }
        });
    });
});

// --- PUBLIC EVENT ROUTES ---

// Get All Events (Public + Pending for now as requested)
app.get('/api/events', (req, res) => {
    const sql = `
        SELECT e.*, u.name as organizer 
        FROM events e 
        LEFT JOIN users u ON e.organizer_id = u.id
        ORDER BY e.date ASC
    `;
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// --- ADMIN EVENT ROUTES ---

// Get Pending Events
app.get('/api/admin/events/pending', authenticateToken, verifyAdmin, (req, res) => {
    const sql = `
        SELECT e.*, u.name as organizer_name 
        FROM events e 
        LEFT JOIN users u ON e.organizer_id = u.id
        WHERE e.status = 'pending'
        ORDER BY e.created_at DESC
    `;

    db.all(sql, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

// Approve/Reject Event
app.put('/api/admin/events/:id/status', authenticateToken, verifyAdmin, (req, res) => {
    const { status } = req.body; // 'approved' or 'rejected'
    const { id } = req.params;

    if (!['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status' });
    }

    const sql = `UPDATE events SET status = ? WHERE id = ?`;
    db.run(sql, [status, id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: `Event ${status} successfully` });
    });
});

// Test Route
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Backend is running' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
