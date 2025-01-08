const mongoose = require('mongoose');
require('dotenv').config();

// Set strictQuery to true for future compatibility with Mongoose 7+
mongoose.set('strictQuery', true);

// Connect to MongoDB using the latest connection string
mongoose
	.connect(process.env.DB_URL)
	.then(() => {
		console.log('Successfully connected to MongoDB');
	})
	.catch((err) => {
		console.error('Error connecting to MongoDB:', err.message);
		process.exit(1); // Exit the process if connection fails
	});

module.exports = mongoose.connection;
