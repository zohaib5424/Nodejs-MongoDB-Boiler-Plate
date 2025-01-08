var mongoose = require('mongoose');

var Schema = mongoose.Schema;
var user = new Schema({
	firstname: {
		type: String,
		required: true,
	},
	lastname: {
		type: String,
		required: true,
	},
	gender: String,
	email: {
		type: String,
		required: false,
	},
	phoneNo: {
		type: String,
		required: false,
	},
	password: {
		type: String,
		required: true,
	},
	role: {
		type: String,
		default: 'USER',
		enum: ['USER', 'ADMIN'],
	},
	profilepic: String,
	address: String,
	isDeleted: {
		type: Boolean,
		default: false,
	},
	resetPasswordOtp: String,
});

module.exports = mongoose.model('User', user);
