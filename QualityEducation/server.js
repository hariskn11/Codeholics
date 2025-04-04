const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', '*');
    next();
});

// Database Setup
const db = new sqlite3.Database(path.join(__dirname, 'users.db'), (err) => {
    if (err) {
        console.error('Database connection error:', err);
        process.exit(1);
    }
    console.log('Connected to SQLite database');
});

// Create tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS student_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        standard TEXT NOT NULL,
        school_name TEXT NOT NULL,
        dob TEXT NOT NULL,
        medium TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
});

// Database helper functions
const dbRun = (sql, params) => new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
        err ? reject(err) : resolve(this);
    });
});

const dbGet = (sql, params) => new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
        err ? reject(err) : resolve(row);
    });
});

const dbAll = (sql, params) => new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
        err ? reject(err) : resolve(rows);
    });
});

// Basic authentication middleware for admin routes
const adminAuth = (req, res, next) => {
    const auth = { login: 'admin', password: 'admin123' };
    const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');
    
    if (login === auth.login && password === auth.password) {
        return next();
    }
    res.set('WWW-Authenticate', 'Basic realm="Admin Access"');
    res.status(401).send('Authentication required');
};

// API Endpoints
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
        if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Invalid username format' });
        if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });
        if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await dbRun(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );
        res.json({ userId: result.lastID, username });
    } catch (error) {
        handleDbError(error, res, 'signup');
    }
});

app.post('/api/signup/details', async (req, res) => {
    try {
        const { userId, standard, school_name, dob, medium } = req.body;
        if (!userId || !standard || !school_name || !dob || !medium) {
            return res.status(400).json({ error: 'All fields required' });
        }

        await dbRun(
            'INSERT INTO student_details (user_id, standard, school_name, dob, medium) VALUES (?, ?, ?, ?, ?)',
            [userId, standard, school_name, dob, medium]
        );
        res.json({ message: 'Details saved successfully', userId });
    } catch (error) {
        handleDbError(error, res, 'save details');
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Credentials required' });

        const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        const validPass = await bcrypt.compare(password, user.password);
        validPass ? res.json({ userId: user.id, username: user.username })
                  : res.status(401).json({ error: 'Invalid credentials' });
    } catch (error) {
        handleDbError(error, res, 'login');
    }
});

app.post('/api/profile', async (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required' });
    }

    try {
        const user = await dbGet(
            `SELECT u.username, u.email, sd.standard, sd.school_name, sd.dob, sd.medium 
             FROM users u 
             LEFT JOIN student_details sd ON u.id = sd.user_id 
             WHERE u.id = ?`,
            [userId]
        );

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Server error fetching profile' });
    }
});

// Admin API endpoints
app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const users = await dbAll('SELECT * FROM users');
        res.json(users);
    } catch (error) {
        handleDbError(error, res, 'fetch users');
    }
});

app.get('/api/admin/student-details', adminAuth, async (req, res) => {
    try {
        const details = await dbAll(`
            SELECT sd.*, u.username 
            FROM student_details sd
            JOIN users u ON sd.user_id = u.id
        `);
        res.json(details);
    } catch (error) {
        handleDbError(error, res, 'fetch student details');
    }
});

// HTML Routes
app.get('/admin.html', adminAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/signup1.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup1.html'));
});

app.get('/home.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/games.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'games.html'));
});

app.get('/codeholics.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'codeholics.html'));
});

app.get('/alp_matching.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'alp_matching.html'));
});

app.get('/fruit_basket.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'fruit_basket.html'));
});

app.get('/grammar_detective.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'grammar_detective.html'));
});

app.get('/listern_repeat.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'listern_repeat.html'));
});

app.get('/phonics_sound.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'phonics_sound.html'));
});

app.get('/sentence_builder.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sentence_builder.html'));
});

app.get('/story_rhyme.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'story_rhyme.html'));
});

app.get('*', (req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Error handler
const handleDbError = (error, res, context) => {
    console.error(`Database error (${context}):`, error);
    if (error.code === 'SQLITE_CONSTRAINT') {
        const field = error.message.includes('username') ? 'Username' : 'Email';
        res.status(400).json({ error: `${field} already exists` });
    } else {
        res.status(500).json({ error: `Server error during ${context}` });
    }
};

// Graceful shutdown
const shutdown = () => {
    db.close((err) => {
        if (err) console.error('Database closure error:', err);
        console.log('Server shutdown gracefully');
        process.exit(0);
    });
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin access: http://localhost:${PORT}/admin.html`);
    console.log('Admin credentials: admin / admin123');
});