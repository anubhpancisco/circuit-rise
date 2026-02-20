const express = require('express');
const cors = require('cors');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,  // Disable CSP to allow iframe embedding
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false
}));

// Explicitly allow iframe embedding from anywhere
app.use((req, res, next) => {
    res.removeHeader('X-Frame-Options');
    res.setHeader('X-Frame-Options', 'ALLOWALL');
    res.setHeader('Content-Security-Policy', "frame-ancestors *");
    next();
});

// CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            /\.articulate\.com$/,
            /\.rise\.com$/,
            /localhost/,
            /127\.0\.0\.1/
        ];

        if (!origin) return callback(null, true);

        if (allowedOrigins.some(pattern => pattern.test(origin))) {
            callback(null, true);
        } else {
            callback(null, true);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '5mb' }));
app.use(express.static('public'));

// Rate limiting
const chatLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' }
});

app.use('/api/circuit/chat', chatLimiter);

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        service: 'CircuIT MCP Server',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
});

// Cisco Chat API Configuration
const CISCO_CHAT_API = {
    url: 'https://chat-ai.cisco.com/openai/deployments/gpt-4o-mini/chat/completions',
    apiKey: process.env.CISCO_API_KEY,
    appKey: process.env.CISCO_APP_KEY,
    timeout: 30000
};

const ciscoAPI = axios.create({
    baseURL: 'https://chat-ai.cisco.com',
    timeout: CISCO_CHAT_API.timeout,
    headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'api-key': CISCO_CHAT_API.apiKey
    }
});

// Storage
const conversations = new Map();

// Build system prompt
function buildSystemPrompt(context) {
    const currentDate = new Date().toLocaleDateString('en-US', { 
        weekday: 'long',
        year: 'numeric', 
        month: 'long', 
        day: 'numeric' 
    });

    return `You are CircuIT, Cisco's universal AI assistant designed to help users find and understand general information.

Current Context:
- Date: ${currentDate}
- Course: ${context.courseName || 'Training Course'}
- Learner: ${context.userName || 'Learner'}

Provide helpful, accurate, and safe responses. Be concise and relevant to the learning context.`;
}

// Main chat endpoint
app.post('/api/circuit/chat', async (req, res) => {
    const requestId = crypto.randomBytes(8).toString('hex');

    try {
        const { message, context = {}, history = [] } = req.body;

        if (!message || typeof message !== 'string' || message.trim().length === 0) {
            return res.status(400).json({ 
                error: 'Message is required',
                requestId
            });
        }

        if (message.length > 4000) {
            return res.status(400).json({ 
                error: 'Message too long (max 4000 characters)',
                requestId
            });
        }

        const fullContext = {
            userId: context.userId || 'user_' + Date.now(),
            userName: context.userName || 'Learner',
            courseId: context.courseId || 'course_' + Date.now(),
            courseName: context.courseName || 'Training Course',
            timestamp: new Date().toISOString()
        };

        const conversationId = `${fullContext.userId}_${fullContext.courseId}`;

        if (!conversations.has(conversationId)) {
            conversations.set(conversationId, { messages: [] });
        }

        const conversation = conversations.get(conversationId);

        const messages = [
            { role: 'system', content: buildSystemPrompt(fullContext) },
            ...history.slice(-10),
            { role: 'user', content: message }
        ];

        console.log(`[${requestId}] Request: "${message.substring(0, 50)}..."`);

        const ciscoResponse = await ciscoAPI.post(
            '/openai/deployments/gpt-4o-mini/chat/completions',
            {
                messages: messages,
                user: JSON.stringify({
                    appkey: CISCO_CHAT_API.appKey,
                    userId: fullContext.userId
                }),
                stop: ["<|im_end|>"],
                max_tokens: 1000,
                temperature: 0.7
            }
        );

        const assistantMessage = ciscoResponse.data.choices[0].message.content;

        console.log(`[${requestId}] Response: "${assistantMessage.substring(0, 50)}..."`);

        conversation.messages.push(
            { role: 'user', content: message, timestamp: Date.now() },
            { role: 'assistant', content: assistantMessage, timestamp: Date.now() }
        );

        if (conversation.messages.length > 50) {
            conversation.messages = conversation.messages.slice(-50);
        }

        res.json({
            success: true,
            response: assistantMessage,
            conversationId: conversationId,
            requestId: requestId,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error(`[${requestId}] Error:`, error.message);

        if (error.response?.status === 401) {
            return res.status(500).json({ 
                error: 'Authentication failed with Cisco API',
                requestId
            });
        }
        
        if (error.response?.status === 429) {
            return res.status(429).json({ 
                error: 'Rate limit exceeded',
                requestId
            });
        }

        res.status(500).json({ 
            error: 'Error processing request',
            requestId
        });
    }
});

// Start server
const server = app.listen(PORT, () => {
    console.log('========================================');
    console.log('CircuIT MCP Server');
    console.log('========================================');
    console.log(`Port: ${PORT}`);
    console.log(`URL: http://localhost:${PORT}`);
    console.log(`Widget: http://localhost:${PORT}/circuit-widget.html`);
    console.log('========================================');
});

process.on('SIGTERM', () => {
    server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
    server.close(() => process.exit(0));
});


module.exports = app;
