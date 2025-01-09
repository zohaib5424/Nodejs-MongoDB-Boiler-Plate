const validateRequest = (schema) => {
	return (req, res, next) => {
		try {
			// Validate the request body with `stripUnknown` option
			const { error, value } = schema.validate(req.body, {
				stripUnknown: true,
			});

			if (error) {
				// Log validation error for debugging purposes
				console.error('Validation Error:', error.details);

				// Send a consistent error response
				return res.status(400).json({
					success: false,
					message: error.details[0].message,
				});
			}

			// Replace request body with sanitized value (no extra fields)
			req.body = value;

			// Proceed to the next middleware or route handler
			next();
		} catch (err) {
			// Handle unexpected errors gracefully
			console.error('Unexpected Validation Middleware Error:', err);
			return res.status(500).json({
				success: false,
				message: 'Internal server error',
			});
		}
	};
};

export default validateRequest;
