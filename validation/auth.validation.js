const Joi = require('joi');

const userRegisterValidationSchema = Joi.object({
	firstName: Joi.string().required(),
	lastName: Joi.string().required(),
	userName: Joi.string().required(),
	gender: Joi.string().valid('male', 'female', 'other').optional(),
	email: Joi.string().email().required(), // Email is required and must be in valid format
	phoneNum: Joi.string()
		.required() // Phone number is required
		.pattern(/^\+?[1-9]\d{6,14}$/) // International phone number validation regex
		.messages({
			'string.pattern.base':
				'Phone number must be a valid international format (e.g., +123456789).',
			'any.required': 'Phone number is required.',
		}),
	password: Joi.string()
		.min(8)
		.required()
		.regex(
			/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
		)
		.messages({
			'string.pattern.base':
				'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
		}), // Password must have at least 8 characters, 1 uppercase, 1 lowercase, 1 number, and 1 special character
	role: Joi.string().valid('USER', 'ADMIN').default('USER'),
	profilePic: Joi.string().optional(),
	address: Joi.string().required(), // Address is now required
	zipCode: Joi.string().optional(),
	country: Joi.string().optional(),
	state: Joi.string().optional(),
	city: Joi.string().optional(),
	isDeleted: Joi.boolean().optional(),
	resetPasswordOtp: Joi.string().optional(),
	dob: Joi.date().optional(),
});

const login = Joi.object({
	email: Joi.string().email().required(), // Email is required and must be in valid format
	password: Joi.string()
		.min(8)
		.required()
		.regex(
			/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
		)
		.messages({
			'string.pattern.base':
				'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
		}), // Password must have at least 8 characters, 1 uppercase, 1 lowercase, 1 number, and 1 special character
});

module.exports = { userRegisterValidationSchema, login };
