var express = require('express');
var router = express.Router();
var authController = require('../controllers/auth.controller');
const authValidation = require('../validation/auth.validation');
const deserializeUser = require('../middlewares/deserializeUser');
const validate = require('../middlewares/validateRequest').default;

router.post(
	'/register',
	validate(authValidation.userRegisterValidationSchema),
	authController.registerUser
);
router.post(
	'/login',
	validate(authValidation.login),
	authController.loginHandler
);

//Route for getting forget password
router.post('/forgetpassword', authController.forgetPassword);
router.post('/verifyotp', authController.verifyOtp);
router.post('/resetpassword', authController.resetPassword);

//protected routes
router.use(deserializeUser);

// Verify Google Authenticator OTP
router.post('/verify-otp', authController.verifyOtpHandler);
// Setup Google Authenticator (This work in included in Login api if need used this as opotinal)
router.post('/setup-authenticator', authController.setupAuthenticator);

router.post('/change-password', authController.changePassword);

module.exports = router;
