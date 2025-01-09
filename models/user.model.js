var mongoose = require('mongoose');

var Schema = mongoose.Schema;
var user = new Schema(
	{
		firstName: {
			type: String,
			required: true,
		},
		lastName: {
			type: String,
			required: true,
		},
		userName: {
			type: String,
			required: true,
		},
		gender: {
			type: String,
		},
		email: {
			type: String,
			required: true,
		},
		phoneNum: {
			type: String,
			required: true,
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
		profilePic: {
			type: String,
		},
		address: {
			type: String,
			required: true,
		},
		zipCode: {
			type: String,
		},
		country: {
			type: String,
		},
		state: {
			type: String,
		},
		city: {
			type: String,
		},
		isDeleted: {
			type: Boolean,
			default: false,
		},
		resetPasswordOtp: {
			type: String,
		},
		otpCreatedAt: { type: Date },
		dob: {
			type: Date,
		},

		twofaSecret: { type: String }, // Google Authenticator secret key
		twofaEnabled: { type: Boolean, default: false },
	},
	{ timestamps: true }
);

module.exports = mongoose.model('User', user);
