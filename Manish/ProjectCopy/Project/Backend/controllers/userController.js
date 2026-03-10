import { User } from "../models/userSchema.js";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import { exec } from "child_process";

export const register = async (req, res) => {
    try {
        const {username,password } = req.body;
        // basic validation
        if (!username || !password) {
            return res.status(401).json({
                message: "All fields are required.",
                success: false
            })
        }
        const user = await User.findOne({ username });
        if (user) {
            return res.status(401).json({
                message: "User already exist.",
                success: false
            })
        }
        const hashedPassword = await bcryptjs.hash(password, 16);

        await User.create({
            username,
            password: hashedPassword
        });
        return res.status(201).json({
            message: "Account created successfully.",
            success: true
        })

    } catch (error) {
        console.log(error);
    }
}
export const login = async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(401).json({
                message: "All fields are required.",
                success: false
            })
        };
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({
                message: "Incorrect email or password",
                success: false
            })
        }
        const isMatch = await bcryptjs.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                message: "Incorect email or password",
                success: false
            });
        }
        const tokenData = {
            userId: user._id
        }
        const token = await jwt.sign(tokenData, process.env.TOKEN_SECRET, { expiresIn: "1d" });
        return res.status(201).cookie("token", token, { expiresIn: "1d", httpOnly: true }).json({
            message: `Welcome back ${user.name}`,
            user,
            success: true
        })
    } catch (error) {
        console.log(error);
    }
}
export const logout = (req, res) => {
    return res.cookie("token", "", { expiresIn: new Date(Date.now()) }).json({
        message: "user logged out successfully.",
        success: true
    })
}

export const restart = async (req, res) => {
    try {

        const playbookPath = "/path/to/your/playbook.yml";  // Change this to your actual path

        exec(`ansible-playbook ${playbookPath}`, (error, stdout, stderr) => {
            if (error) {
                console.log("Exec error:", error);
                return res.status(500).json({
                    success: false,
                    message: "Failed to restart machines.",
                    error: error.message
                });
            }

            if (stderr) {
                console.log("Ansible stderr:", stderr);
                // stderr doesn't always mean failure, but return it anyway
                return res.status(200).json({
                    success: true,
                    message: "Restart initiated with warnings.",
                    output: stderr
                });
            }

            // Success
            return res.status(200).json({
                success: true,
                message: "Machines restarted successfully!",
                output: stdout
            });
        });

    } catch (error) {
        console.log("Controller error:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

export const upgrade = async (req, res) => {
    try {

        const playbookPath = "/path/to/your/playbook.yml";   

        exec(`ansible-playbook ${playbookPath}`, (error, stdout, stderr) => {
            if (error) {
                console.log("Exec error:", error);
                return res.status(500).json({
                    success: false,
                    message: "Failed to restart machines.",
                    error: error.message
                });
            }

            if (stderr) {
                console.log("Ansible stderr:", stderr);
                 
                return res.status(200).json({
                    success: true,
                    message: "Restart initiated with warnings.",
                    output: stderr
                });
            }

            // Success
            return res.status(200).json({
                success: true,
                message: "Machines restarted successfully!",
                output: stdout
            });
        });

    } catch (error) {
        console.log("Controller error:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};
