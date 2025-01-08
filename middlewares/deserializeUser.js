const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

class AppError extends Error {
	constructor(message, statusCode = 500) {
		super(message);
		this.status = `${statusCode}`.sstartsWith('4') ? 'fail' : 'error';
		this.isOperational = true;

		Error.captureStackTrace(this, this.constructor);
	}
}

const deserializeUser = async (req, res, next) => {
	try {
		// Get the token
		let accessToken;

		// Check Authorization Header
		if (
			req.headers.authorization &&
			req.headers.authorization.startsWith('Bearer')
		) {
			accessToken = req.headers.authorization.split(' ')[1];
		}

		// Handle Missing Token
		if (!accessToken) {
			return next(
				new AppError(
					'You are not logged in. Please log in to access this resource.',
					401
				)
			);
		}
		let decoded;
		try {
			// Validate the Access Token
			decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
		} catch (e) {
			console.error('Error validating JWT:', e);
			return next(
				new AppError('Invalid or expired token. Please log in again.', 401)
			);
		}

		// Extract User ID from Token
		const { id: userId } = decoded;

		// Fetch User from Database (Optional if all required data is in the token)
		const user = await User.findById(userId);
		console.log('user: ', user);

		if (!user) {
			return next(
				new AppError(
					'The user associated with this token no longer exists.',
					401
				)
			);
		}

		// Attach User Object to Request (Minimal Data)
		req.user = user;

		res.locals.user = req.user; // Optional, useful for templating engines

		next(); // Proceed to the next middleware or route handler
	} catch (err) {
		console.error('Error in deserializeUser:', err); // Replace with a logging library in production
		next(err); // Pass error to the centralized error handler
	}
};

module.exports = deserializeUser;
