var User = require('../models/user.model');
const bcrypt = require('bcrypt');
const saltRounds = 10; //process.env.BCRYPT_SALT_ROUNDS
var jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const otpGenerator = require('otp-generator');
const { sendEmail } = require('../helpers/sendEmail');
const { sendMessage } = require('../helpers/sendMessage');

const setupGoogleAuthenticator = async (user, projectName) => {
	try {
		// Generate a new secret for Google Authenticator
		const secret = speakeasy.generateSecret({
			length: 32,
		});

		// Construct the otpauth URL manually
		const otpauthUrl = `otpauth://totp/${encodeURIComponent(projectName)}:${encodeURIComponent(
			user.email
		)}?secret=${secret.base32}&issuer=${encodeURIComponent(projectName)}`;

		// Save the secret to the database
		user.twofaSecret = secret.base32; // Save the base32 secret
		await user.save();

		// Generate a QR code for the user to scan with Google Authenticator
		const qrCodeUrl = await QRCode.toDataURL(otpauthUrl);

		// Return the QR code URL and manual entry key
		return {
			qrCodeUrl,
			manualKey: secret.base32,
		};
	} catch (err) {
		console.error('Error setting up Google Authenticator:', err);
		throw new Error('Failed to set up Google Authenticator');
	}
};

const generateUniqueOtp = async (length = 6) => {
	try {
		let isUnique = false;
		let otp;

		while (!isUnique) {
			// Generate a new OTP
			otp = otpGenerator.generate(length, {
				upperCaseAlphabets: false,
				specialChars: false,
			});

			// Check if the OTP already exists in the database
			const existingUser = await User.findOne({ resetPasswordOtp: otp });

			// If no user has this OTP, it is unique
			if (!existingUser) {
				isUnique = true;
			}
		}

		return otp;
	} catch (err) {
		console.error('Error generating unique OTP:', err);
		throw new Error('Failed to generate unique OTP');
	}
};

const registerUser = async (req, res) => {
	try {
		const userData = req.body;
		const existingUser = await User.findOne({ email: userData.email });
		if (existingUser) {
			if (existingUser.isDeleted) {
				return res.status(400).json({
					error:
						'This user account is marked as deleted. Please contact support.',
				});
			}
			return res
				.status(400)
				.json({ error: 'User with this email already exists' });
		}

		if (userData.password) {
			userData.password = await bcrypt.hash(userData.password, saltRounds);
		}
		const user = new User(userData);
		await user.save();

		return res.status(201).json({
			message: 'User registered successfully',
			user: {
				id: user._id,
				firstName: user.firstName,
				lastName: user.lastName,
				email: user.email,
				role: user.role,
			},
		});
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: 'Internal server error' });
	}
};

const loginHandler = async (req, res) => {
	try {
		const { email, password } = req.body;

		// Find the user by email
		const user = await User.findOne({ email });
		if (!user) {
			return res
				.status(401)
				.json({ success: false, message: 'Invalid email or password' });
		}

		// Validate password
		const isPasswordValid = await bcrypt.compare(password, user.password);
		if (!isPasswordValid) {
			return res
				.status(401)
				.json({ success: false, message: 'Invalid email or password' });
		}

		// Generate a temporary token (valid for 5 minutes)
		const tempToken = jwt.sign({ id: user._id }, process.env.LOGIN_JWT_SECRET, {
			expiresIn: '5m',
		});

		// If 2FA is not enabled, prompt the user to set it up
		// if (!user.twofaEnabled) {
		// 	return res.status(200).json({
		// 		success: true,
		// 		message: '2FA is not enabled. Please set up your authenticator app.',
		// 		firstTimeSetup: true,
		// 		tempToken,
		// 	});
		// }
		if (!user.twofaEnabled) {
			const setupDetails = await setupGoogleAuthenticator(user, 'Traddoo');

			return res.status(200).json({
				success: true,
				message: '2FA is not enabled. Please set up your authenticator app.',
				firstTimeSetup: true,
				tempToken, // Include the temporary token for future API calls
				setupDetails, // Include QR code and manual key
			});
		}

		return res.status(200).json({
			success: true,
			message: 'Email and password validated. Proceed to OTP verification.',
			tempToken,
		});
	} catch (err) {
		console.error(err);
		res.status(500).json({ success: false, message: 'Internal server error' });
	}
};

const setupAuthenticator = async (req, res) => {
	try {
		const userId = req.user._id;

		// Find the user by ID
		const user = await User.findById(userId);
		if (!user) {
			return res
				.status(404)
				.json({ success: false, message: 'User not found' });
		}

		const setupDetails = await setupGoogleAuthenticator(user, 'Traddoo');

		return res.status(200).json({
			success: true,
			message: 'Scan the QR code with your Google Authenticator app',
			setupDetails,
		});
	} catch (err) {
		console.error(err);
		res
			.status(500)
			.json({ success: false, message: 'Failed to set up authenticator' });
	}
};

const verifyOtpHandler = async (req, res) => {
	try {
		const { otp } = req.body;
		if (!otp) {
			return res
				.status(400)
				.json({ success: false, message: 'OTP is required' });
		}
		const userId = req.user._id;

		// Find the user by ID
		const user = await User.findById(userId);
		if (!user) {
			return res
				.status(404)
				.json({ success: false, message: 'User not found' });
		}

		// Verify the OTP using the user's Google Authenticator secret
		const isOtpValid = speakeasy.totp.verify({
			secret: user.twofaSecret, // User's secret stored in the database
			encoding: 'base32',
			token: otp, // OTP sent by the client
		});

		if (!isOtpValid) {
			return res.status(400).json({ success: false, message: 'Invalid OTP' });
		}

		// Enable 2FA if this is the first time the user is verifying OTP
		if (!user.twofaEnabled) {
			user.twofaEnabled = true; // Enable 2FA
			await user.save();
		}

		// Generate access and refresh tokens for the logged-in session
		const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
			expiresIn: process.env.EXPIRES_IN,
		});
		const refreshToken = jwt.sign(
			{ userId: user._id },
			process.env.JWT_SECRET,
			{
				expiresIn: '7d',
			}
		);

		const returnUser = {
			id: user._id,
			firstName: user.firstName,
			lastName: user.lastName,
			userName: user.userName,
			email: user.email,
			role: user.role,
		};

		return res.status(200).json({
			success: true,
			message: 'OTP verification successful',
			user: returnUser,
			accessToken,
			refreshToken,
		});
	} catch (err) {
		console.error(err);
		res
			.status(500)
			.json({ success: false, message: 'OTP verification failed' });
	}
};

const forgetPassword = async (req, res) => {
	try {
		const { email, phoneNum } = req.body;

		// Determine the query based on the input
		let query = {};
		if (email) {
			query = { email };
		} else if (phoneNum) {
			query = { phoneNum };
		} else {
			return res.status(400).json({
				success: false,
				message: 'Please provide either email or phone number!',
			});
		}

		// Find user in database
		const user = await User.findOne(query);

		if (!user) {
			return res.status(404).json({
				success: false,
				message: `User not found with this ${
					email ? 'email' : 'phone number'
				}!`,
			});
		}

		// Generate a unique OTP
		const otp = await generateUniqueOtp();
		const otpExpiryTime = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now

		user.otpExpiryTime = otpExpiryTime;
		user.resetPasswordOtp = otp;
		await user.save();

		// Example: Send OTP via email
		// await sendEmail(email, 'Reset Password', `Your OTP is: ${otp}`);

		// Success response
		return res.status(200).json({
			success: true,
			message: `Reset Password OTP sent to ${email}.`,
		});
	} catch (err) {
		// Log the error and return a 500 response
		console.error('Error in forgetPassword API:', err);
		return res.status(500).json({
			success: false,
			message: 'Internal Server Error',
		});
	}
};
const verifyOtp = async (req, res) => {
	try {
		const { otp } = req.body;

		// Check if OTP is provided
		if (!otp) {
			return res.status(400).json({
				success: false,
				message: 'OTP is required!',
			});
		}

		// Find the user by OTP
		const user = await User.findOne({ resetPasswordOtp: otp });

		if (!user) {
			return res.status(404).json({
				success: false,
				message: 'Invalid OTP. Please try again!',
			});
		}

		// Check if the OTP is expired
		const isOtpExpired = new Date() > new Date(user.otpExpiryTime);
		if (isOtpExpired) {
			return res.status(400).json({
				success: false,
				message: 'OTP has expired. Please request a new one!',
			});
		}

		const otpExpiryTime = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now(Extend more 10 minutes after veify)

		user.otpExpiryTime = otpExpiryTime;
		user.save();

		// OTP is valid; allow user to proceed with password reset
		return res.status(200).json({
			success: true,
			message: 'OTP verified successfully. You can now reset your password.',
		});
	} catch (err) {
		console.error('Error in verifyOtp API:', err);
		return res.status(500).json({
			success: false,
			message: 'Internal Server Error',
		});
	}
};

const resetPassword = async (req, res) => {
	try {
		const { otp, newPassword } = req.body;

		if (!otp || !newPassword) {
			return res.status(400).json({
				success: false,
				message: 'OTP and new password are required!',
			});
		}

		const user = await User.findOne({ resetPasswordOtp: otp });

		if (!user) {
			return res.status(404).json({
				success: false,
				message: 'Invalid OTP. Please try again!',
			});
		}

		const isOtpExpired = new Date() > new Date(user.otpExpiryTime);
		if (isOtpExpired) {
			return res.status(400).json({
				success: false,
				message: 'OTP has expired. Please request a new one!',
			});
		}

		// Validate password strength
		const passwordRegex =
			/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

		if (!passwordRegex.test(newPassword)) {
			return res.status(400).json({
				success: false,
				message:
					'Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.',
			});
		}

		// Hash the new password
		const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

		// Update user's password and clear OTP fields
		user.password = hashedPassword;
		user.resetPasswordOtp = null; // Clear the OTP
		user.otpExpiryTime = null; // Clear the OTP expiry time
		await user.save();

		// Respond with success
		return res.status(200).json({
			success: true,
			message: 'Password reset successfully!',
		});
	} catch (err) {
		console.error('Error in resetPassword API:', err);
		return res.status(500).json({
			success: false,
			message: 'Internal Server Error',
		});
	}
};

const changePassword = async (req, res) => {
	try {
		// Get request body data
		const { currentPassword, newPassword } = req.body;

		// Validate request body
		if (!currentPassword || !newPassword) {
			return res.status(400).json({
				success: false,
				message: 'Current password and new password are required!',
			});
		}

		// Validate new password strength at the start
		const passwordRegex =
			/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

		if (!passwordRegex.test(newPassword)) {
			return res.status(400).json({
				success: false,
				message:
					'New password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.',
			});
		}

		// Ensure new password is not the same as the current password
		if (currentPassword === newPassword) {
			return res.status(400).json({
				success: false,
				message: 'New password must be different from the current password!',
			});
		}

		// Get user ID from req.user (assumes authentication middleware has populated req.user)
		const userId = req.body.userId || req.user._id;

		// Find the user in the database
		const user = await User.findById(userId);

		if (!user) {
			return res.status(404).json({
				success: false,
				message: 'User not found!',
			});
		}

		// Verify the current password
		const isPasswordValid = await bcrypt.compare(
			currentPassword,
			user.password
		);

		if (!isPasswordValid) {
			return res.status(400).json({
				success: false,
				message: 'Current password is incorrect!',
			});
		}

		// Hash the new password
		const hashedNewPassword = await bcrypt.hash(newPassword, 10);

		// Update user's password in the database
		user.password = hashedNewPassword;
		await user.save();

		// Respond with success
		return res.status(200).json({
			success: true,
			message: 'Password changed successfully!',
		});
	} catch (err) {
		console.error('Error in changePassword API:', err);
		return res.status(500).json({
			success: false,
			message: 'Internal Server Error',
		});
	}
};

module.exports = {
	registerUser,

	loginHandler,
	setupAuthenticator,
	verifyOtpHandler,

	forgetPassword,
	verifyOtp,
	resetPassword,

	changePassword,
};
