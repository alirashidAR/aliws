const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8000;
const jwtSecret = 'your_secret_key';

// Log when starting the database connection
console.log('Connecting to the database...');

const pool = new Pool({
    connectionString: process.env.DATABASE_URI,
});

// Log to confirm connection to the database
pool.connect()
    .then(() => console.log('Database connected successfully.'))
    .catch(err => console.error('Error connecting to the database:', err));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.use(express.static('styles'));

// Models
class Admin {
    constructor(id, username, password) {
        this.id = id;
        this.username = username;
        this.password = password;
    }
}

class DailyBlog {
    constructor(title, content) {
        this.title = title;
        this.content = content;
    }
}

// Routes
app.get('/', index);
app.get('/addblogs', addBlogs);
app.get('/readinglist', readingList);
app.get('/blogs', blogsPage);
app.get('/projects', projects);
app.post('/login', login);
app.post('/addblogs', authMiddleware, createBlog);

// Middleware for authentication
function authMiddleware(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        req.user = user;
        next();
    });
}

// Handlers
function index(req, res) {
    res.render('index');
}

function addBlogs(req, res) {
    res.render('addblogs');
}

function readingList(req, res) {
    res.render('reading-list');
}

function projects(req, res) {
    res.render('projects');
}

async function blogsPage(req, res) {
    try {
        const result = await pool.query('SELECT title, description FROM blogs');
        const blogs = result.rows.map(row => new DailyBlog(row.title, row.description));
        res.render('blogs', { blogs });
    } catch (err) {
        console.error('Error reading the blogs:', err);
        res.status(500).json({ error: 'Error reading the blogs' });
    }
}

async function createBlog(req, res) {
    const { title, content } = req.body;

    if (!title || !content) {
        return res.status(400).json({ error: 'Content and Title cannot be empty' });
    }

    const uuid = require('uuid').v4();
    const query = 'INSERT INTO blogs (id, title, description) VALUES ($1, $2, $3)';

    try {
        await pool.query(query, [uuid, title, content]);
        res.status(201).json(new DailyBlog(title, content));
    } catch (err) {
        console.error('Error creating the blog:', err);
        res.status(500).json({ error: 'Error creating the blog' });
    }
}

async function login(req, res) {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and Password cannot be empty.' });
    }

    const query = 'SELECT id, password FROM admin WHERE username = $1';
    try {
        const result = await pool.query(query, [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const storedPassword = result.rows[0].password;
        const match = await bcrypt.compare(password, storedPassword);
        if (!match) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ username }, jwtSecret, { expiresIn: '72h' });
        res.cookie('token', token, { maxAge: 3600 * 72 * 1000, httpOnly: true });
        res.render('login_success', { message: 'Login successful' });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
}

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
