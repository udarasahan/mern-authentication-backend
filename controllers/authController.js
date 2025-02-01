import bcrypt from 'bcryptjs';
import { jwt } from 'jsonwebtoken';
import userModel from '../models/userModel';

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
    } catch (error) {
        res.json({success: false, message: error.message});
    }
}