const express = require('express');
const session = require('express-session');
const path = require('path');
const db = require('./config/db.config');
const authRoutes = require('./routes/auth.routes');

const app = express();

// Middleware for session management
app.use(session({
    secret: 'secretkey',  // Replace with a secure secret in production
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // Use true for HTTPS
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.use('/', authRoutes);

// Start the server
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
