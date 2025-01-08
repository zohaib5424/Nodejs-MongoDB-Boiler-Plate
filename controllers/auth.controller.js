var User = require('../models/user.model');
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
const { sendEmail } = require('../helpers/sendEmail');
const { sendMessage } = require('../helpers/sendMessage');

const createUser = async (req, res) => {
	try {
		const email = req.body.email.toLowerCase();
		var phoneno = req.body.phoneno;
		var ifuser;
		ifuser = await User.findOne({
			$or: [{ phoneno: phoneno }, { email: email }],
		});
		if (ifuser) {
			if (ifuser.isDeleted == true) {
				return res.status(200).send({
					success: false,
					message: 'This User is Deleted.',
					data: [],
				});
			} else {
				return res.status(200).send({
					success: false,
					message: 'User Already Exists.',
				});
			}
		} else {
			//encrypting user password
			const encryptedPassword = await bcrypt.hash(
				req.body.password,
				saltRounds
			);
			//saving user to DB
			console.log('req.files: ', req.files);
			var newUser;
			newUser = await new User({
				firstname: req.body.firstname,
				lastname: req.body.lastname,
				email: email,
				address: req.body.address,
				phoneno: phoneno,
				role: req.body.role,
				profilepic: req.files
					? req.files.length > 0
						? '/src/' + req.files[0].filename
						: null
					: null,
				password: encryptedPassword,
				companyId: req?.body?.companyId,
			}).save();
			if (newUser) {
				console.log('You are now user', newUser);
				res.status(200).send({
					success: true,
					message: 'You are now user',
					data: newUser,
				});
			} else {
				console.log('Request Failed');
				res.status(404).send({
					success: false,
					message: 'Request Failed',
				});
			}
		}
	} catch (err) {
		console.log('err.isJoi: ', err);
		if (err.isJoi) {
			res.status(422).json({
				success: false,
				message: err.details[0].message,
			});
		} else {
			res.status(500).json({
				success: false,
				message: err,
			});
		}
	}
};
const login = async (req, res) => {
	try {
		const { email, phoneno, password } = req.body;

		// email = email.toLowerCase();
		const user = await User.findOne({
			$or: [{ phoneno: phoneno }, { email: email }],
		});
		if (user) {
			if (user.isDeleted == true) {
				return res.send(400).json({
					success: false,
					message: 'User not exists',
				});
			}
			if (await bcrypt.compare(password, user.password)) {
				const accessToken = await jwt.sign(
					{ id: user._id },
					process.env.JWT_SECRET,
					{
						expiresIn: process.env.EXPIRES_IN,
					}
				);
				return res.status(200).json({
					success: true,
					message: 'Correct Details',
					user: user,
					accessToken: accessToken,
				});
			} else {
				return res.status(400).json({
					success: false,
					message: 'Error: Email and Pass Dont Match',
				});
			}
		} else {
			console.log('Invalid User');
			return res.status(400).json({
				success: false,
				message: 'User not exists',
			});
		}
	} catch (err) {
		console.log('err.isJoi: ', err);
		return res.status(500).json({
			success: false,
			message: 'Internal Server Error',
		});
	}
};
const forgetPassword = async (req, res) => {
	try {
		const { email, phoneno } = req.body;
		if (email) {
			User.findOne({
				email: req.body.email,
			})
				.then(async (user) => {
					console.log('user', user);
					//Checking If User Exists
					if (!user) {
						return res.status(404).json({
							success: false,
							message: 'User not found with this Email!',
						});
					}
					//Creating Reset OTP for SMS
					var otp = otpGenerator.generate(6, {
						upperCaseAlphabets: false,
						specialChars: false,
					});

					const number = req.body.phoneno;
					console.log('numberrr: ', number);

					//Sending Reset OTP to email
					const emailSent = await sendEmail(
						req.body.email,
						'Reset Password',
						`Reset Password OTP: ${otp}`
					);

					if (!emailSent) {
						return console.log('error occurs');
					}

					user.resetPasswordOtp = otp;
					return user.save();
				})
				.then((result) => {
					return res.status(200).send({
						success: true,
						message: 'Reset Password Email sent',
					});
				})
				.catch((err) => {
					console.log(err);
				});
		} else if (phoneno) {
			User.findOne({
				phoneno: req.body.phoneno,
			})
				.then(async (user) => {
					console.log('user', user);
					//Checking If User Exists
					if (!user) {
						return res.status(404).json({
							success: false,
							message: 'User not found with this Email!',
						});
					}
					//Creating Reset OTP for SMS
					var otp = otpGenerator.generate(6, {
						upperCaseAlphabets: false,
						specialChars: false,
					});

					const number = req.body.phoneno;
					console.log('numberrr: ', number);

					//Sending Reset OTP to phone
					const messageSent = await sendMessage(
						number,
						`Reset Password OTP: ${otp}`
					);

					if (!messageSent) {
						return console.log('error occurs');
					}

					user.resetPasswordOtp = otp;
					return user.save();
				})
				.then((result) => {
					return res.status(200).send({
						success: true,
						message: 'Reset Password message sent',
					});
				})
				.catch((err) => {
					console.log(err);
				});
		}
	} catch (err) {
		console.log('err.isJoi: ', err);
		if (err.isJoi) {
			res.status(422).json({
				success: false,
				message: err.details[0].message,
			});
		} else {
			return res.status(500).json({
				success: false,
				message: 'Internal Server Error',
			});
		}
	}
};
const verifyOTP = async (req, res) => {
	try {
		console.log('U are ', req.body);
		//Finding user with the reset OTP
		User.findOne({ resetPasswordOtp: req.body.resetPasswordOtp }).then(
			(user) => {
				//If User don't exist with the given resetOTP, give error
				console.log('user ', user);
				if (!user) {
					return res.status(404).json({
						success: false,
						message: 'Invalid OTP',
					});
				} else {
					//If User exists with the given resetOTP then send success
					return res.status(200).json({
						success: true,
						user: user,
						message: 'OTP Verified. User Can Change The Password',
					});
				}
			}
		);
	} catch (err) {
		console.log(err);
		if (err.isJoi) {
			res.status(422).json({
				success: false,
				message: err.details[0].message,
			});
		} else {
			res.status(500).json({
				success: false,
				message: 'Internal Server Error',
			});
		}
	}
};
const resetPassword = async (req, res) => {
	try {
		console.log('req.body', req.body);
		try {
			//Encrypting new password
			let encryptedPassword = await bcrypt.hash(req.body.password, saltRounds);
			console.log('encryptedPassword: ', encryptedPassword);
			//Updating password
			const updatePassword = await User.updateOne(
				{ resetPasswordOtp: req.body.otp },
				{
					$set: {
						resetPasswordOtp: null,
						password: encryptedPassword,
					},
				}
			);
			console.log('updatePassword: ', updatePassword);
			if (updatePassword?.nModified > 0)
				return res.status(200).json({
					success: true,
					message: 'Password Updated',
				});
			else
				return res.status(401).json({
					success: false,
					message: 'Otp not valid',
				});
		} catch (err) {
			res.status(500).json({
				success: false,
				message: 'internal server error',
			});
		}
	} catch (err) {
		console.log('err.isJoi: ', err);
		if (err.isJoi) {
			res.status(422).json({
				success: false,
				message: err.details[0].message,
			});
		} else {
			res.status(500).json({
				success: false,
				message: 'Internal Server Error',
			});
		}
	}
};

module.exports = {
	createUser,
	login,
	forgetPassword,
	verifyOTP,
	resetPassword,
};
