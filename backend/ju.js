require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = 5000;

// Secrets
const ACCESS_TOKEN_SECRET = "payweek_access_secret";
const REFRESH_TOKEN_SECRET = "payweek_refresh_secret";

// Middleware
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Database Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "payweek",
    database: "auth_app",
});

db.connect((err) => {
    if (err) throw err;
    console.log("Database connected.");
});

// Utility Functions
const generateAccessToken = (user) => jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
const generateRefreshToken = (user) => jwt.sign(user, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

// Register User
app.post("/register", async (req, res) => {
    const { first_name, last_name, email, phone, password } = req.body;
    if (!first_name || !last_name || !email || !phone || !password) {
        return res.status(400).send("All fields are required.");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
        "INSERT INTO users (first_name, last_name, email, phone, password) VALUES (?, ?, ?, ?, ?)",
        [first_name, last_name, email, phone, hashedPassword],
        (err) => {
            if (err) return res.status(500).send("User already exists.");
            res.status(201).send("User registered successfully.");
        }
    );
});

// Login User and Generate OTP
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const ipAddress = req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).send("Server error.");
        if (results.length === 0) return res.status(401).send("Invalid credentials.");

        const user = results[0];
        if (user.is_disabled) return res.status(403).send("User account is disabled.");

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).send("Invalid credentials.");

        const otp = generateOtp();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

        db.query(
            "INSERT INTO otps (user_id, otp, ip_address, expires_at) VALUES (?, ?, ?, ?)",
            [user.id, otp, ipAddress, expiresAt],
            (otpErr) => {
                if (otpErr) return res.status(500).send("Error generating OTP.");

                console.log(`Generated OTP for ${email}: ${otp}`); // Display OTP in terminal for now
                res.status(200).send({
                    message: "OTP generated. Check terminal for OTP.",
                    userId: user.id,
                });
            }
        );
    });
});

// Verify OTP
app.post("/verify-otp", (req, res) => {
    const { userId, otp } = req.body;
    const ipAddress = req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    db.query(
        "SELECT * FROM otps WHERE user_id = ? AND otp = ? AND ip_address = ? AND expires_at > NOW()",
        [userId, otp, ipAddress],
        (err, results) => {
            if (err || results.length === 0) {
                return res.status(401).send("Invalid or expired OTP.");
            }

            db.query("DELETE FROM otps WHERE user_id = ? AND ip_address = ?", [userId, ipAddress]);

            const accessToken = generateAccessToken({ id: userId });
            const refreshToken = generateRefreshToken({ id: userId });

            db.query(
                "INSERT INTO refresh_tokens (user_id, token, ip_address) VALUES (?, ?, ?)",
                [userId, refreshToken, ipAddress],
                (tokenErr) => {
                    if (tokenErr) return res.status(500).send("Error saving refresh token.");

                    res.cookie("refreshToken", refreshToken, { httpOnly: true });
                    res.json({ accessToken });
                }
            );
        }
    );
});

// Refresh Token
app.post("/refresh-token", (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(403).send("Refresh token required.");

    db.query("SELECT * FROM refresh_tokens WHERE token = ?", [refreshToken], (err, results) => {
        if (err || results.length === 0) return res.status(403).send("Invalid refresh token.");

        jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
            if (err) return res.status(403).send("Token verification failed.");

            const accessToken = generateAccessToken({ id: decoded.id });
            res.json({ accessToken });
        });
    });
});

// Logout
app.post("/logout", (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(400).send("Refresh token required.");

    db.query("DELETE FROM refresh_tokens WHERE token = ?", [refreshToken], (err) => {
        if (err) return res.status(500).send("Failed to revoke refresh token.");
        res.clearCookie("refreshToken");
        res.send("Logged out successfully.");
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
