var express = require('express');
var router = express.Router();
var authController = require('../controllers/auth.controller');
const deserializeUser = require('../middlewares/deserializeUser');

//Route for registering after verification
router.post('/', authController.createUser);
//Route for registering after verification
router.post('/login', authController.login);

//Route for verifying forget password otp
router.post('/verifyotp', authController.verifyOTP);
//Route for getting forget password otp on email
router.post('/resetpassword', authController.resetPassword);

//protected routes
router.use(deserializeUser);
//Route for getting forget password otp on email
router.post('/forgetpassword', authController.forgetPassword);

module.exports = router;
