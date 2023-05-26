const express = require('express')
const { route } = require('express/lib/router')
const router = express.Router()

const {
	allUser,
	register,
	loginUser,
	sendOTP,
	verifyOTP,
    updateProfile,
    changePassword,
	deleteAccount,
    forgetPassword,
    resetPassword,
} = require('../controller/user');

// //all user
router.route('/').get(allUser)
// //signup
router.route('/register').post(register)
// //login
router.route('/login').post(loginUser)
// //send otp
router.route('/send').post(sendOTP);
// //verify otp
router.route('/verify').post(verifyOTP)

// //updateProfile
router.put('/update', updateProfile)

// //delete User
router.delete('/delete_account', deleteAccount)

// //forgetPassword
router.post('/forget_password', forgetPassword)

// //change Password
router.post('/change_password', changePassword)

// //reset Password
router.get('/reset_password/:id/:token', resetPassword)







module.exports = router