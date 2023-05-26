const User = require('../model/user');
const { StatusCodes } = require('http-status-codes');
const customError = require('../errors');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
// const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');
const OTP = require('../model/otp');
const jwt = require('jsonwebtoken');
const validator = require('validator');

const transporter = nodemailer.createTransport({
	service: 'gmail',
	auth: {
		user: process.env.EMAIL,
		pass: process.env.PASSWORD,
	},
});

// const createToken = (_id) => {
// 	return jwt.sign({ _id }, process.env.JWT_SECRET, { expiresIn: '3m' });
// };

const allUser = async (req, res) => {
	const users = await User.find();
	if (!users) {
		res.status(401).json({ status: 409, message: 'user not exist' });
	}

	res.status(200).json(users);
};

const register = async (req, res) => {
	const { fname, lname, email, password, phone } = req.body;
	if (!fname || !lname || !email || !password) {
		throw new customError.UnauthenticatedError(
			'Please provide valid credentials'
		);
	}
	// //Validator
	if (!validator.isStrongPassword(password)) {
		throw new customError.UnauthenticatedError('Input a strong password');
	}

	const phoneexists = await User.findOne({ phone });
	const emailexists = await User.findOne({ email });

	if (phoneexists) {
		throw new customError.UnauthenticatedError(
			'Phone Number already in use my another account !!'
		);
	}
	if (emailexists) {
		throw new customError.UnauthenticatedError(
			'Email already in use my another account !!'
		);
	}

	const user = await User.create(req.body);

	res.status(StatusCodes.CREATED).json({
		user: {
			id: user._id,
			fname: user.fname,
			lname: user.lname,
			phone: user.phone,
			email: user.email,
			role: user.role,
			createdAt: user.createdAt,
		},
	});
};

const loginUser = async (req, res) => {
	const { email, password } = req.body;

	if (!email || !password) {
		throw new customError.UnauthenticatedError(
			'Please provide valid credentials'
		);
	}

	const user = await User.findOne({ email });

	if (!user) {
		throw new customError.NotFoundError('User not found please register');
	}

	const comparedPassword = await user.compares(password);

	if (!comparedPassword) {
		throw new customError.UnauthenticatedError(
			'please provide valid credentials'
		);
	}

	const token = user.Createjwt();

	res.status(StatusCodes.OK).json({
		user: {
			id: user._id,
			fname: user.fname,
			lname: user.lname,
			email: user.email,
			role: user.role,
			token,
			msg: 'logged in successful',
		},
	});
};

const sendEmail = async (req, res) => {
	try {
		const { email } = req.body;
		const checkUser = User.findOne({ email });
		if (checkUser) {
			const otp = `${Math.floor(1000 + Math.random() * 9000)}`;

			const salt = 10;
			const hashedOTP = await bcrypt.hash(otp, salt);
			const currentTime = new Date().getTime();

			const savedOTP = new OTP({
				otp: hashedOTP,
				email: email,
				createdWhen: `${currentTime}`,
				expiresWhen: `${currentTime + 120000}`,
			});

			await savedOTP.save();

			const mailoption = {
				from: `${process.env.SENDERMAIL}`, // sender address
				to: email, // receivers address
				subject: 'Email for  OTP Verication', // Subject line
				text: `Verify your Account by using this OTP: ${otp} valid for 3 Minutes`, // plain text body
				html: `Verify your Account by using this OTP <b>${otp}</b> in your app, valid for 3 Minutes`, //html
			};

			transporter.sendMail(mailoption, (error, info) => {
				if (error) {
					// console.log(error, "error");
					res.status(401).json({
						error: error,
						message: 'OTP code sent successfully',
					});
				} else {
					// console.log(info.response, "success");
					res.status(StatusCodes.OK).json({
						status: 'PENDING',
						info,
						message: 'OTP code sent successfully',
					});
				}
			});
		}
	} catch (error) {
		res
			.status(StatusCodes.BAD_REQUEST)
			.json({ status: 'FAILED', msg: 'Verication FAILED to send to Email' });
		console.log(error);
	}
};

const sendOTP = async (req, res) => {
	const { email } = req.body;
	const checkOTPUser = await OTP.findOne({ email });

	if (checkOTPUser) {
		await OTP.deleteOne({ email });
		sendEmail(req, res);
	} else {
		sendEmail(req, res);
		res
			.status(StatusCodes.OK)
			.json({ status: 'PENDING', msg: 'Verication OTP sent to Email' });
	}
};

const verifyOTP = async (req, res) => {
	const { email, otp } = req.body;

	if (!email || !otp) {
		throw new customError.NotFoundError('please provide valid credentials');
	} else {
		const user = await User.findOne({ email });
		const otpUser = await OTP.findOne({ email });

		if (!user) {
			throw new customError.NotFoundError('User not found');
		} else {
			const otpVerify = otpUser.otp;
			const userLL = await bcrypt.compare(otp, otpVerify);
			const exp = otpUser.expiresWhen;

			if (Number(exp) > Number(Date.now()) && userLL) {
				const token = user.Createjwt();
				res
					.status(StatusCodes.OK)
					.json({ msg: 'User Verified!', AccessToken: token });
			} else {
				await OTP.deleteMany({ email });
				res.status(StatusCodes.BAD_REQUEST).json({ msg: 'User OTP expired' });
			}
		}
	}
};

const forgetPassword = async (req, res) => {
	const { email } = req.body;
	try {
		if (!email) {
			throw new customError.NotFoundError('Email is required!');
		}

		const user = await User.findOne({ email });

		if (!user) {
			throw new customError.NotFoundError('User not found please register!');
		}
		// create a token
		const token = user.Createjwt();
		const link = `${process.env.URL}/api/v1/user/reset_password/${user._id}/${token}`;

		const mailoption = {
			from: `${process.env.SENDERMAIL}`, // sender address
			to: email, // receivers address
			subject: 'Email for Password Reset', // Subject line
			text: `This Link is valid for 3 Minutes ${link}`, // plain text body
			html: `<p>This Link is valid for 3 Minutes ${link}</p>`,
		};

		transporter.sendMail(mailoption, (error, info) => {
			if (error) {
				// console.log(error, "error");
				res.status(401).json({
					error: error,
					message: 'Password reset link sent successfully',
				});
			} else {
				// console.log(info.response, "success");
				res.status(200).json({
					token,
					info,
					message: 'Password reset link sent successfully',
				});
			}
		});
	} catch (error) {
		res.status(404).json({ error: error || error.message });
	}
};
// // user profile
const updateProfile = async (req, res) => {
	const { id } = req.body;
	const formData = req.body;
	try {
		if (!id || !mongoose.isValidObjectId(id)) {
      throw new customError.NotFoundError('Enter a valid user ID');
    }
		if (!formData) {
			throw new customError.NotFoundError('enter a data');
		}
		const updateUser = await User.findByIdAndUpdate({ _id: id }, formData, { new: true });
		if (updateUser) {
			res
				.status(200)
				.json({ user: updateUser, msg: 'Profile updated successfully' });
		} else {
			throw new customError.NotFoundError('User not found');
		}
	} catch (error) {
		res.status(404).json({ error: error.message || error});
	}
};

// // reset Password
const resetPassword = async (req, res) => {
	const { id, token } = req.params;
	try {
		let user = await User.find({ _id: id });

		if (!user) {
			throw new customError.NotFoundError('User does not  exist!!');
		}
		// // verify the token
		const verify = jwt.verify(token, process.env.JWT_SECRET);

		if (!verify) {
			throw new customError.NotFoundError('verification failed');
		}
		res
			.status(200)
			.json({ user, verify, token, message: 'Password Reset Successfully' });
	} catch (error) {
		res
			.status(401)
			.json({ error: error || error.message, message: 'Something went wrong' });
	}
};

// // change Password
const changePassword = async (req, res) => {
	const { id, token, password, confirmPassword } = req.body;
	try {
		// // verify the token
		const verify = jwt.verify(token, process.env.JWT_SECRET);
		if (!verify) {
			throw new customError.UnauthenticatedError('verification failed');
		}
		if (!validator.isStrongPassword(password)) {
			throw new customError.UnauthenticatedError('Input a strong password');
    }
    if (password !== confirmPassword) {
			throw new customError.UnauthenticatedError(
				'Password and confirm password must match'
			);
		}

		const salt = await bcrypt.genSalt(10);
		const hash = await bcrypt.hash(password, salt);
		let user = await User.findByIdAndUpdate({ _id: id }, { password: hash });

		user = await user.save();
		res.status(200).json({ user, message: 'Password Changed Successfully' });
	} catch (error) {
		res.status(404).json({ error: error.message || error});
	}
};

// // delete account
const deleteAccount = async (req, res) => {
	const { id } = req.body;

	const user = await User.findByIdAndDelete({ _id: id });
	if (!user) {
		res.status(401).json({ status: 401, message: 'user not exist' });
	}

	res.status(200).json({ message: 'Account Deleted Successfully' });
};
module.exports = {
	allUser,
	register,
	loginUser,
	sendOTP,
	verifyOTP,
	updateProfile,
	forgetPassword,
	resetPassword,
	changePassword,
	deleteAccount,
};
