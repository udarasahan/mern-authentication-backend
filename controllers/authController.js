import bcrypt from 'bcryptjs';
import userModel from '../models/userModel.js';
import jwt from 'jsonwebtoken';
import transporter from '../config/nodemailer.js'

export const register = async (req,res) => {
    const {name, email, password} = req.body;

    if(!name || !email || !password) {
        return res.json({success: false, message: 'Please enter all fields'});
    }

    try {
        const existingUser = await userModel.findOne({email});
        if (existingUser) {
            return res.json({success: false, message: 'User already exists'});
        }
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({
            name,
            email,
            password: hashedPassword,
        });
        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '5d'});

        res.cookie('token', token, {httpOnly: true, // Send cookies only over HTTPS
            secure: process.allowedNodeEnvironmentFlags.NODE_ENV === 'production', 
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 5 * 24 * 60 * 60 * 1000
        });

        // Sending Welcome Email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to MERN Auth',
            text: `Hello ${user.name}, Welcome to MERN Auth. Your account has been created with email id: ${email}`,
        }

        await transporter.sendMail(mailOptions);

        return res.json({seccess: true, message: 'User created successfully'});

    } catch (error) {
        res.json({success: false, message: error.message});
    }
}

export const login = async (req,res) => {
    const {email, password} = req.body;
    
    if(!email || !password) {
        return res.json({success: false, messafe: 'Email and password are required'});
    }

    try {
        const user =  await userModel.findOne({email});

        if (!user) {
            return res.json({success: false, message: 'Invalid email or password'});
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({success: false, message: 'Invalid email or password'});
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '5d'});

        res.cookie('token', token, {httpOnly: true, // Send cookies only over HTTPS
            secure: process.allowedNodeEnvironmentFlags.NODE_ENV === 'production', 
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 5 * 24 * 60 * 60 * 1000
        });

        return res.json({success: true, message: 'Login success'});
        
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const logout = async (req,res) => {
    try {
        res.clearCookie('token', {httpOnly: true, // Send cookies only over HTTPS
            secure: process.allowedNodeEnvironmentFlags.NODE_ENV === 'production', 
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'});

            return res.json({success: true, message: 'Logged out successfully'});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const sendVerifyOtp = async (req,res) => {
    try {
        const {userId} = req.body;

        const user =  await userModel.findById(userId);

        if(user.isAccountVerified) {
            return res.json({success: false, message: 'Account already verified'});
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 10 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Hello ${user.name}, Your OTP for account verification is ${otp}`,
        }

        await transporter.sendMail(mailOptions);

        res.json({success: true, message: 'OTP sent successfully'});
    } catch (error) {
        return res.json({success: false, message: error.message});
        
    }
}

export const verifyEmail  = async (req,res) => {
    
    const {userId, otp} = req.body;

    if(!userId || !otp) {
        return res.json({success: false, message: "Missing Details"});
    }
    
    try {
        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({success: false, message: 'User not found'});
            }

            if (user.verifyOtp === '' || user.verifyOtp !== otp) {
                return res.json({success: false, message: 'Invalid OTP'});
            }

            if (user.verifyOtpExpireAt < Date.now()) {
                return res.json({success: false, message: 'OTP expired'});
            }

            user.isAccountVerified = true;
            user.verifyOtp = '';
            user.verifyOtpExpireAt = 0;

            user.save();
            return res.json({success: true, message: 'Account verified successfully'});

        } catch (error) {
            return res.json({success: false, message: error.message});
    }
}

// Check if user is already authenticated
export const isAuthenticated = async (req,res) => {
    try {
        return res.json({success: true, message: 'Authenticated'});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

// Send Password reset otp
export const sendResetOtp = async (req,res) => {
    const {email} = req.body;

    if (!email) {
        return res.json({success: false, message: 'Email is required'});
    }

    try {
        const user = await userModel.findOne({email});

        if (!user) {
            return res.json({success: false, message: 'User not found'});
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 8 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Hello ${user.name}, Your OTP for password reset is ${otp}`,
        }

        await transporter.sendMail(mailOptions);

        res.json({success: true, message: 'OTP sent successfully'});
        

    } catch (error) {
        return res.json({success: false, message: error.message});
        
    }
}

// Reset User Password
export const resetPassword = async (req,res) => {
    const {email, otp, newPassword} =  req.body;

    if(!email || !otp || !newPassword) {
        return res.json({ success: false, message: "Email, otp and password are required" })
    }

    try {
        const user = await userModel.findOne({email})

        if (!user) {
            return res.json({success: false, message: "User not found"});
        }
        if(user.resetOtp === "" || user.resetOtp !== otp) {
            return res.json({success: false, message: "Invalid OTP"})
        }
        if(user.resetOtpExpireAt < Date.now()) {
            return res.json({success: false, message: "OTP is expired"})
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        return res.json({success: true, message: "Password reset Successfull"})

    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}