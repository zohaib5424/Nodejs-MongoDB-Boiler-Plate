var express = require('express');
var createError = require('http-errors');
require('dotenv').config();
var cors = require('cors');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
const expressSanitizer = require('express-sanitizer');

const db = require('./config/dbConfig');
const errorHandlerMiddleware = require('./middlewares/error-handler');
var authRoutes = require('./routes/auth.routes');

var app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(logger('dev'));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(expressSanitizer());

// Routes
app.use('/api/auth', authRoutes);

// Catch 404 and forward to error handler
app.use(function (req, res, next) {
	next(createError(404, 'Route not found'));
});

// Error Handling Middleware
app.use(errorHandlerMiddleware); // Handles all errors (including 404s)

// Start server
app.listen(port, () => {
	console.log(`Server is running on http://localhost:${port}`);
});
