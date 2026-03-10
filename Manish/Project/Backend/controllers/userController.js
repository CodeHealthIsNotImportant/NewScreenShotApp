import { User } from "../models/userSchema.js";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import { exec } from "child_process";

export const register = async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                message: "All fields are required.",
                success: false
            });
        }

        const userExists = await User.findOne({ username });
        if (userExists) {
            return res.status(400).json({
                message: "User already exists.",
                success: false
            });
        }

        const hashedPassword = await bcryptjs.hash(password, 16);

        const user = await User.create({
            username,
            password: hashedPassword
        });

        return res.status(201).json({
            message: "Account created successfully.",
            success: true
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            message: "Internal server error",
            success: false
        });
    }
};

export const login = async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                message: "All fields are required.",
                success: false
            });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({
                message: "Incorrect username or password",
                success: false
            });
        }

        const isMatch = await bcryptjs.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                message: "Incorrect username or password",
                success: false
            });
        }

        const token = jwt.sign({ userId: user._id }, process.env.TOKEN_SECRET, { expiresIn: "1d" });

        return res.status(200)
            .cookie("token", token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }) // 1 day
            .json({
                message: `Welcome back ${user.username}`,
                user,
                success: true
            });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            message: "Internal server error",
            success: false
        });
    }
};

export const logout = (req, res) => {
    return res.cookie("token", "", { expires: new Date(0), httpOnly: true }).json({
        message: "User logged out successfully.",
        success: true
    });
};
