import bcrypt from 'bcryptjs';
import userModel from '../models/userModel.js';
import jwt from 'jsonwebtoken';

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