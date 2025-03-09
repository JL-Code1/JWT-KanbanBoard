import { Router } from "express";
import { User } from "../models/user.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
const router = Router();
// POST /login - Authenticate user and return a JWT token
export const login = async (req, res) => {
    try {
        const { username, password } = req.body;
        // 1️⃣ Check if the user exists in the database
        const user = await User.findOne({ where: { username } });
        if (!user) {
            return res.status(401).json({ message: "Invalid username or password" });
        }
        // 2️⃣ Verify password using bcrypt
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid username or password" });
        }
        // 3️⃣ Generate a JWT token
        const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: "1h" } // Token expires in 1 hour
        );
        // 4️⃣ Return the token
        return res.json({ token });
    }
    catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ message: "Server error" });
    }
};
// Register login route
router.post("/login", login);
export default router;
