import express from "express";
import { login, register, logout } from "../controllers/userController.js";
import isAuthenticated from "../config/auth.js"; // if you plan to protect routes later

const router = express.Router();

// Registration route
router.post("/register", register);

// Login route
router.post("/login", login);

// Logout route
router.get("/logout", logout);

// Example of a protected route (optional)
// router.get("/profile", isAuthenticated, (req, res) => {
//     res.status(200).json({ message: "Protected route access granted", user: req.user });
// });

export default router;
