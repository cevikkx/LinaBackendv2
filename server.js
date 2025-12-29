const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_change_in_prod';
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';

// Security Middleware
app.use(helmet()); // Sets various HTTP headers for security
app.use(cors()); // Configure this strictly in production (e.g., origin: 'https://your-app.com')
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// PostgreSQL Connection Pool
// Connection string format: postgres://user:password@host:port/database
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test Database Connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('Error acquiring client', err.stack);
        console.log('WARNING: Make sure your .env has a valid DATABASE_URL');
    } else {
        console.log('Connected to PostgreSQL database');
        initDatabase();
        release();
    }
});

async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at BIGINT
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                user_id TEXT REFERENCES users(id),
                title TEXT,
                last_message TEXT,
                last_message_time BIGINT,
                created_at BIGINT,
                unread_count INTEGER DEFAULT 0
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT REFERENCES conversations(id) ON DELETE CASCADE,
                content TEXT,
                sender TEXT,
                timestamp BIGINT,
                is_read INTEGER DEFAULT 0
            );
        `);
        console.log('Database tables verified/created');
    } catch (err) {
        console.error('Error initializing database:', err);
    }
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// OpenRouter API Call
// OpenRouter API Call
async function callOpenRouter(messages) {
    if (!OPENROUTER_API_KEY) {
        throw new Error('OpenRouter API Key is missing.');
    }

    // LINA PERSONA (System Prompt)
    const systemPrompt = {
        role: "system",
        content: `Senin adın Lina. Samimi, neşeli ve dert dinleyen yakın bir kız arkadaşsın.
Amacın, kullanıcıyla sohbet etmek, ona moral vermek ve arkadaşlık etmek.
Konuşma dilin günlük ve rahat olmalı, 3-4 mesajda bir emoji kullan.
Sohbetlere başlarken kendini tanıtma, direkt konuya girerek samimi bir şekilde cevap ver.
Kullanıcı bir sorun anlattığında onu anladığını belli et ve destek ol.
Resmi bir dil kullanmaktan ve bir yapay zeka olduğunu söylemekten kaçın.`
    };

    // Prepend system prompt to the conversation history
    const allMessages = [systemPrompt, ...messages];

    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
            "Content-Type": "application/json",
            "HTTP-Referer": "https://lina-app.com",
            "X-Title": "Lina App"
        },
        body: JSON.stringify({
            model: "openai/gpt-3.5-turbo",
            messages: allMessages,
        })
    });

    if (!response.ok) {
        const err = await response.text();
        throw new Error(`OpenRouter API Error: ${err}`);
    }

    const data = await response.json();
    return data.choices[0].message.content;
}

// Routes

// Register
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const id = uuidv4();
        const created_at = Date.now();

        await pool.query(
            `INSERT INTO users (id, username, password, created_at) VALUES ($1, $2, $3, $4)`,
            [id, username, hashedPassword, created_at]
        );
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        if (error.code === '23505') { // Postgres UNIQUE_VIOLATION
            return res.status(400).json({ error: 'Username already exists' });
        }
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
        const user = result.rows[0];

        if (!user) return res.status(400).json({ error: 'User not found' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username: user.username, userId: user.id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Conversations
app.get('/api/conversations', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM conversations WHERE user_id = $1 ORDER BY last_message_time DESC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create Conversation
app.post('/api/conversations', authenticateToken, async (req, res) => {
    const id = uuidv4();
    const title = 'Yeni Sohbet';
    const now = Date.now();
    const userId = req.user.id;

    try {
        await pool.query(
            `INSERT INTO conversations (id, user_id, title, last_message, last_message_time, created_at, unread_count) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [id, userId, title, '', now, now, 0]
        );
        res.json({ id, title, last_message: '', last_message_time: now, created_at: now });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Messages
app.get('/api/conversations/:id/messages', authenticateToken, async (req, res) => {
    const conversationId = req.params.id;
    const userId = req.user.id;

    try {
        const check = await pool.query(`SELECT user_id FROM conversations WHERE id = $1`, [conversationId]);
        if (check.rows.length === 0) return res.status(404).json({ error: 'Conversation not found' });
        if (check.rows[0].user_id !== userId) return res.status(403).json({ error: 'Access denied' });

        const result = await pool.query(
            `SELECT * FROM messages WHERE conversation_id = $1 ORDER BY timestamp ASC`,
            [conversationId]
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Send Message
app.post('/api/conversations/:id/messages', authenticateToken, async (req, res) => {
    const conversationId = req.params.id;
    const { content } = req.body;
    const userId = req.user.id;

    if (!content) return res.status(400).json({ error: 'Content required' });

    try {
        const check = await pool.query(`SELECT user_id FROM conversations WHERE id = $1`, [conversationId]);
        if (check.rows.length === 0) return res.status(404).json({ error: 'Conversation not found' });
        if (check.rows[0].user_id !== userId) return res.status(403).json({ error: 'Access denied' });

        const userMessageId = uuidv4();
        const timestamp = Date.now();

        // 1. Save User Message
        await pool.query(
            `INSERT INTO messages (id, conversation_id, content, sender, timestamp, is_read) VALUES ($1, $2, $3, $4, $5, $6)`,
            [userMessageId, conversationId, content, 'user', timestamp, 1]
        );

        // 2. Get History
        const historyRes = await pool.query(
            `SELECT content, sender FROM messages WHERE conversation_id = $1 ORDER BY timestamp ASC LIMIT 50`,
            [conversationId]
        );

        const apiMessages = historyRes.rows.map(msg => ({
            role: msg.sender === 'user' ? 'user' : 'assistant',
            content: msg.content
        }));

        // 3. Call AI
        const aiResponse = await callOpenRouter(apiMessages);

        // 4. Save AI Message
        const aiMessageId = uuidv4();
        const aiTimestamp = Date.now();

        await pool.query(
            `INSERT INTO messages (id, conversation_id, content, sender, timestamp, is_read) VALUES ($1, $2, $3, $4, $5, $6)`,
            [aiMessageId, conversationId, aiResponse, 'lina', aiTimestamp, 0]
        );

        // 5. Update Conversation
        await pool.query(
            `UPDATE conversations SET last_message = $1, last_message_time = $2, unread_count = unread_count + 1 WHERE id = $3`,
            [aiResponse, aiTimestamp, conversationId]
        );

        res.json({
            userMessage: { id: userMessageId, conversation_id: conversationId, content, sender: 'user', timestamp: timestamp, is_read: 1 },
            linaMessage: { id: aiMessageId, conversation_id: conversationId, content: aiResponse, sender: 'lina', timestamp: aiTimestamp, is_read: 0 }
        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update Title
app.put('/api/conversations/:id/title', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title } = req.body;
    const userId = req.user.id;

    if (!title) return res.status(400).json({ error: 'Title is required' });

    try {
        const result = await pool.query(
            `UPDATE conversations SET title = $1 WHERE id = $2 AND user_id = $3 RETURNING *`,
            [title, id, userId]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Conversation not found or access denied' });
        res.json({ success: true, id, newTitle: title });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete Conversation
app.delete('/api/conversations/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const result = await pool.query(
            `DELETE FROM conversations WHERE id = $1 AND user_id = $2`,
            [id, userId]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Conversation not found or access denied' });
        // Cascade delete will handle messages
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health & Ready Check
app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', database: 'connected', timestamp: Date.now() });
    } catch (e) {
        res.status(500).json({ status: 'error', database: 'disconnected', error: e.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Lina API server running on port ${PORT}`);
});

process.on('SIGINT', async () => {
    await pool.end();
    console.log('Database pool closed');
    process.exit(0);
});