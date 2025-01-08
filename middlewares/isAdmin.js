const isAdmin = (req, res, next) => {
	// Check if the user is authenticated
	if (!req.user) {
		console.log('User is not authenticated');
		return res.status(401).json({
			success: false,
			message: 'You are not logged in. Please log in to access this resource.',
		});
	}

	// Check if the user's role is ADMIN
	if (req.user.role !== 'ADMIN') {
		console.log('User is not an Admin');
		return res.status(403).json({
			success: false,
			message: 'Access denied. You do not have admin privileges.',
		});
	}

	console.log('User is an Admin');
	next(); // Proceed to the next middleware or route handler
};

module.exports = isAdmin;
