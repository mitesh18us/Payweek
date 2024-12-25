const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { PDFDocument, rgb, StandardFonts } = require("pdf-lib");
require('dotenv').config();
//const twilio = require('twilio');
const nodemailer = require("nodemailer");

// Twilio client initialization
//const twilioClient = twilio(
 //   process.env.TWILIO_ACCOUNT_SID,
//    process.env.TWILIO_AUTH_TOKEN
//);



const app = express();
const PORT = 5000;

// Secrets
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

// Middleware
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DATABASE,
});

db.connect((err) => {
    if (err) throw err;
    console.log("Database connected.");
});

// Utility Functions
const generateAccessToken = (user) => jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: "30m" });
//const generateRefreshToken = (user) => jwt.sign(user, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();










 //Register User
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
            res.status(201).send("User registered.");
        }
    );
});

//Login User//
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const ipAddress = req.headers["x-forwarded-for"] || req.connection.remoteAddress;

        if (!email || !password) {
            return res.status(400).send("Email and password are required.");
        }

        // Fetch user from the database
        db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).send("Server error.");
            }

            if (results.length === 0) {
                return res.status(401).send("Invalid credentials.");
            }

            const user = results[0];

            // Check if the account is disabled
            if (user.is_disabled) {
                return res.status(403).send("User account is disabled.");
            }

            // Validate the password
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).send("Invalid credentials.");
            }

            // Check if there is a refresh token in cookies
            const existingRefreshToken = req.cookies.refreshToken;

            if (existingRefreshToken) {
                // Validate the existing refresh token
                db.query(
                    "SELECT * FROM refresh_tokens WHERE token = ?",
                    [existingRefreshToken],
                    (refreshErr, refreshResults) => {
                        if (refreshErr) {
                            console.error("Refresh token validation error:", refreshErr);
                            return res.status(500).send("Server error.");
                        }

                        if (refreshResults.length > 0) {
                            const storedToken = refreshResults[0];

                            // Check if IP addresses match
                            if (storedToken.ip_address === ipAddress) {
                                // Generate a new access token
                                const accessToken = jwt.sign({ id: user.id }, ACCESS_TOKEN_SECRET, {
                                    expiresIn: "45m",
                                });

                                console.log(`User ${user.email} logged in with existing refresh token.`);

                                // Send access token to the client
                                return res.status(200).send({
                                    message: "Logged in successfully.",
                                    accessToken,
                                });
                            }
                        }

                        // If refresh token is invalid or IP address mismatch, fall back to OTP
                        return issueOtpAndRespond(user, ipAddress, res);
                    }
                );
            } else {
                // No refresh token, issue OTP or log in directly for first-time logins
                return issueOtpAndRespond(user, ipAddress, res);
            }
        });
    } catch (error) {
        console.error("Unexpected error:", error);
        res.status(500).send("An unexpected error occurred.");
    }
});

const issueOtpAndRespond = async (user, ipAddress, res) => {
    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

    // Insert OTP into the database
    db.query(
        "INSERT INTO otps (user_id, otp, ip_address, expires_at) VALUES (?, ?, ?, ?)",
        [user.id, otp, ipAddress, expiresAt],
        async (otpErr) => {
            if (otpErr) {
                console.error("Error inserting OTP:", otpErr);
                return res.status(500).send("Error generating OTP.");
            }

            // Send response to frontend immediately
            res.status(200).send({
                message: "OTP sent to your email. Please verify.",
                userId: user.id,
            });

            // Handle email sending asynchronously
            try {
                const transporter = nodemailer.createTransport({
                    service: "gmail",
                    auth: {
                        user: process.env.GMAIL_EMAIL,
                        pass: process.env.GMAIL_APP_PASSWORD,
                    },
                });

                const mailOptions = {
                    from: process.env.GMAIL_EMAIL,
                    to: user.email,
                    subject: "[Payweek]: Your OTP Code",
                    text: `Your OTP code is: ${otp}. It will expire in 5 minutes.`,
                };

                const info = await transporter.sendMail(mailOptions);
                console.log("Email sent successfully:", info.response);
            } catch (emailErr) {
                console.error("Error sending email:", emailErr);
            }
        }
    );
};



// const issueOtpAndRespond = async (user, ipAddress, res) => {
//     const otp = generateOtp();
//     const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

//     // Insert OTP into the database
//     db.query(
//         "INSERT INTO otps (user_id, otp, ip_address, expires_at) VALUES (?, ?, ?, ?)",
//         [user.id, otp, ipAddress, expiresAt],
//         async (otpErr) => {
//             if (otpErr) {
//                 console.error("Error inserting OTP:", otpErr);
//                 return res.status(500).send("Error generating OTP.");
//             }

//             // Log OTP for testing purposes
//             console.log(`Generated OTP for ${user.email}: ${otp}`);

//             // Send OTP to the user's email using Nodemailer
//             try {
//                 // Create a Nodemailer transporter
//                 const transporter = nodemailer.createTransport({
//                     service: "gmail",
//                     auth: {
//                         user: "mitesh.18us@gmail.com", // Your Gmail address
//                         pass: "bbkw pcbj hnxt gvuk", // Your App Password
//                     },
//                 });

//                 // Email content
//                 const mailOptions = {
//                     from: "mitesh.18us@gmail.com", // Sender's email address
//                     to: user.email, // Recipient's email address
//                     subject: "[Payweek]: Your OTP Code",
//                     text: `Your OTP code is: ${otp}. It will expire in 5 minutes.`,
//                 };

//                 // Send the email
//                 const info = await transporter.sendMail(mailOptions);
//                 console.log("Email sent successfully:", info.response);

//                 // Inform the client to proceed with OTP verification
//                 res.status(200).send({
//                     message: "OTP sent to your email address.",
//                     userId: user.id,
//                 });
//             } catch (emailErr) {
//                 console.error("Error sending email:", emailErr);
//                 res.status(500).send("Failed to send OTP via email.");
//             }
//         }
//     );
// };








// const issueOtpAndRespond = (user, ipAddress, res) => {
//     const otp = generateOtp();
//     const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

//     // Insert OTP into the database
//     db.query(
//         "INSERT INTO otps (user_id, otp, ip_address, expires_at) VALUES (?, ?, ?, ?)",
//         [user.id, otp, ipAddress, expiresAt],
//         (otpErr) => {
//             if (otpErr) {
//                 console.error("Error inserting OTP:", otpErr);
//                 return res.status(500).send("Error generating OTP.");
//             }


//                     // Log OTP for testing purposes
//                     console.log(`Generated OTP for ${user.email}: ${otp}`);

//                     // Inform the client to proceed with OTP verification
//                     res.status(200).send({
//                         message: "OTP generated. Check terminal for OTP.",
//                         userId: user.id,
//                     });
                
            
//         }
//     );
// }; 

// const issueOtpAndRespond = async (user, ipAddress, res) => {
//     const otp = generateOtp();
//     const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

//     // Insert OTP into the database
//     db.query(
//         "INSERT INTO otps (user_id, otp, ip_address, expires_at) VALUES (?, ?, ?, ?)",
//         [user.id, otp, ipAddress, expiresAt],
//         async (otpErr) => {
//             if (otpErr) {
//                 console.error("Error inserting OTP:", otpErr);
//                 return res.status(500).send("Error generating OTP.");
//             }

//             // Log OTP for testing purposes
//             console.log(`Generated OTP for ${user.email}: ${otp}`);

//             // Send OTP to the user's email using Nodemailer
//             try {
//                 // Create a Nodemailer transporter
//                 const transporter = nodemailer.createTransport({
//                     service: "gmail",
//                     auth: {
//                         user: process.env.GMAIL_EMAIL, // Your Gmail address
//                         pass: process.env.GMAIL_APP_PASSWORD, // Generated app password
//                     },
//                 });

//                 // Email content
//                 const mailOptions = {
//                     from: process.env.GMAIL_EMAIL,
//                     to: user.email, // The recipient's email address
//                     subject: "[Payweek]: Your OTP Code",
//                     text: `Your OTP code is: ${otp}. It will expire in 5 minutes.`,
//                 };

//                 // Send the email
//                 const info = await transporter.sendMail(mailOptions);
//                 console.log("Email sent successfully:", info.response);

//                 // Inform the client to proceed with OTP verification
//                 res.status(200).send({
//                     message: "OTP sent to your email address.",
//                     userId: user.id,
//                 });
//             } catch (emailErr) {
//                 console.error("Error sending email:", emailErr);
//                 res.status(500).send("Failed to send OTP via email.");
//             }
//         }
//     );
// };



// const issueOtpAndRespond = async (user, ipAddress, res) => {
//     const otp = generateOtp();
//     const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

//     // Insert OTP into the database
//     db.query(
//         "INSERT INTO otps (user_id, otp, ip_address, expires_at) VALUES (?, ?, ?, ?)",
//         [user.id, otp, ipAddress, expiresAt],
//         async (otpErr) => { // Mark the callback function as async
//             if (otpErr) {
//                 console.error("Error inserting OTP:", otpErr);
//                 return res.status(500).send("Error generating OTP.");
//             }

//             // Log OTP for testing purposes
//             console.log(`Generated OTP for ${user.phone}: ${otp}`);

//             // Send OTP to the user's phone using Twilio
//             try {
//                 const message = await twilioClient.messages.create({
//                     body: `[Payweek]: Your OTP code is: ${otp}. It will expire in 5 minutes.`,
//                     from: process.env.TWILIO_PHONE_NUMBER,
//                     to: user.phone // Ensure user.phone_number has the correct format: +1234567890
//                 });

//                 console.log("SMS sent successfully:", message.sid);

//                 // Inform the client to proceed with OTP verification
//                 res.status(200).send({
//                     message: "OTP sent to your phone number.",
//                     userId: user.id,
//                 });
//             } catch (twilioErr) {
//                 console.error("Error sending SMS:", twilioErr);
//                 res.status(500).send("Failed to send OTP via SMS.");
//             }
//         }
//     );
// };





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

            // Generate a new refresh token
            const refreshToken = jwt.sign({ id: userId }, REFRESH_TOKEN_SECRET, {
                expiresIn: "7d",
                });

                // Store refresh token in the database
                db.query(
                "INSERT INTO refresh_tokens (user_id, token, ip_address) VALUES (?, ?, ?)",
                [userId, refreshToken, ipAddress],
                (tokenErr) => {
                if (tokenErr) {
                    console.error("Error saving refresh token:", tokenErr);
                    return res.status(500).send("Error saving refresh token.");
                }

                // Set the new refresh token as an HTTP-only cookie
                res.cookie("refreshToken", refreshToken, {
                    httpOnly: true,
                    secure: "false",
                    sameSite: "strict",
                    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
                });
            
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




const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).send("Access token required.");

    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).send("Invalid or expired token.");
        req.user = user; // Attach the decoded user to the request
        next();
    });
};








//List of all Businesses//
app.get("/businesses", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from the `authenticate` middleware

    if (!userId) {
        return res.status(401).send("Unauthorized access.");
    }

    // Query businesses associated with the authenticated user
    db.query(
        "SELECT * FROM businesses WHERE owner_id = ? AND is_disabled = FALSE",
        [userId],
        (err, results) => {
            if (err) {
                console.error("Error fetching businesses:", err);
                return res.status(500).send("Error fetching businesses.");
            }

            res.json(results);
        }
    );
});

//Add a New Business//
app.post("/businesses", authenticateToken, (req, res) => {
    const {
        name,
        b_stadd,
        b_suite,
        b_state,
        b_city,
        b_zip,
        start_date,
        end_date,
        pay_date,
        frequency,
    } = req.body;

    if (!name || !b_stadd || !b_state || !b_city || !b_zip) {
        return res.status(400).send("Required fields are missing.");
    }

    const ownerId = req.user.id; // Get the user ID from the token

    db.query(
        `INSERT INTO businesses 
        (name, owner_id, b_stadd, b_suite, b_state, b_city, b_zip, start_date, end_date, pay_date, frequency) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            name,
            ownerId,
            b_stadd,
            b_suite || null,
            b_state,
            b_city,
            b_zip,
            start_date || null,
            end_date || null,
            pay_date || null,
            frequency || null,
        ],
        (err) => {
            if (err) {
                console.error("Error adding business:", err);
                return res.status(500).send("Error adding business.");
            }
            res.status(201).send("Business added successfully.");
        }
    );
});


app.get("/states", (req, res) => {
    db.query("SELECT st_code, st_name FROM us_st", (err, results) => {
        if (err) {
            console.error("Error fetching states:", err);
            return res.status(500).send("Error fetching states.");
        }
        res.status(200).json(results);
    });
});


app.get("/cities/:stateCode", (req, res) => {
    const { stateCode } = req.params;
    db.query("SELECT city_name FROM city_all WHERE state_code = ?", [stateCode], (err, results) => {
        if (err) {
            console.error("Error fetching cities:", err);
            return res.status(500).send("Error fetching cities.");
        }
        res.status(200).json(results);
    });
});



app.get("/businesses/:id", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from the `authenticate` middleware
    const {id:businessId} = req.params;

    if (!userId || !businessId) {
        return res.status(401).send("Unauthorized access.");
    }

    // Query businesses associated with the authenticated user
    db.query(
        "SELECT * FROM businesses WHERE owner_id = ? AND id = ? AND is_disabled = FALSE",
        [userId, businessId],
        (err, results) => {
            if (err) {
                console.error("Error fetching businesses:", err);
                return res.status(500).send("Error fetching businesses.");
            }

            if (results.length === 0) {
                return res.status(404).send("Business not found or unauthorized.");
            }

            res.json(results[0]); // Return the first result

        }
    );
});



//Add New Employee//
app.post("/employees", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from token
    const {
        business_id,
        first_name,
        last_name,
        e_st_add,
        e_suite,
        e_state,
        e_city,
        e_zip,
        dob,
        ssn,
        filing_status,
        dependents,
        additional_fed_tax,
        additional_state_tax,
        salary_amt,
        hourly_amt,
    } = req.body;

    // Validate required fields
    if (!business_id || !first_name || !last_name || !e_st_add || !e_state || !e_city || !e_zip || !dob || !ssn || !filing_status) {
        return res.status(400).send("Missing required fields.");
    }

    // Ensure either salary_amt or hourly_amt is set, but not both
    if ((salary_amt && hourly_amt) || (!salary_amt && !hourly_amt)) {
        return res
            .status(400)
            .send("You must provide either salary_amt or hourly_amt, but not both.");
    }

    // Insert the new employee into the database
    db.query(
        `INSERT INTO employees 
        (business_id, user_id, first_name, last_name, e_st_add, e_suite, e_state, e_city, e_zip, dob, ssn, filing_status, dependents, additional_fed_tax, additional_state_tax, salary_amt, hourly_amt, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
            business_id,
            userId,
            first_name,
            last_name,
            e_st_add,
            e_suite || null,
            e_state,
            e_city,
            e_zip,
            dob,
            ssn,
            filing_status,
            dependents || null,
            additional_fed_tax || null,
            additional_state_tax || null,
            salary_amt || null,
            hourly_amt || null,
        ],
        (err, result) => {
            if (err) {
                console.error("Error adding employee:", err);
                return res.status(500).send("Error adding employee.");
            }
            res.status(201).send("Employee added successfully.");
        }
    );
});






app.put("/employees/:id/disable", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from the token
    const { id: employeeId } = req.params; // Employee ID from the URL

    db.query(
        "UPDATE employees SET disabled_at = NOW(), disabled = 1  WHERE id = ? AND user_id = ?",
        [employeeId, userId],
        (err, result) => {
            if (err) {
                console.error("Error disabling employee:", err);
                return res.status(500).send("Error disabling employee.");
            }

            if (result.affectedRows === 0) {
                return res.status(404).send("Employee not found or unauthorized.");
            }

            // Respond with the updated status
            res.json({
                disabled: true,
                disabled_at: new Date(), // Return the current timestamp
                message: "Employee disabled successfully.",
            });
        }
    );
});


app.put("/employees/:id/enable", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from the token
    const { id: employeeId } = req.params; // Employee ID from the URL

    db.query(
        "UPDATE employees SET disabled_at = NULL, disabled = 0 WHERE id = ? AND user_id = ?",
        [employeeId, userId],
        (err, result) => {
            if (err) {
                console.error("Error enabling employee:", err);
                return res.status(500).send("Error enabling employee.");
            }

            if (result.affectedRows === 0) {
                return res.status(404).send("Employee not found or unauthorized.");
            }

            res.send("Employee enabled successfully.");
        }
    );
});


app.get("/employees/:id/inactive", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from the token
    const { id: businessid } = req.params; // Business ID passed as a query parameter

    // Log the user ID and business ID for debugging
    console.log("Fetching inactive employees...");
    console.log("User ID:", userId);
    console.log("Business ID:", businessid);

    // Check if business_id exists
    if (!businessid) {
        console.error("Business ID is missing in the request.");
        return res.status(400).send("Business ID is required.");
    }

    db.query(
        "SELECT id, first_name, last_name, e_city FROM employees WHERE user_id = ? AND business_id = ? AND disabled_at IS NOT NULL AND disabled = 1",
        [userId, businessid],
        (err, results) => {
            if (err) {
                console.error("Error fetching inactive employees:", err);
                return res.status(500).send("Error fetching inactive employees.");
            }

            if (results.length === 0) {
                console.log("No inactive employees found for the given user and business.");
            } else {
                console.log(`Fetched ${results.length} inactive employees.`);
            }

            res.json(results);
        }
    );
});



// Fetch individual employee
app.get("/business/:businessId/employees/:employeeId", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract authenticated user ID from the token
    const { businessId, employeeId } = req.params; // Extract business and employee IDs from URL

    // Query the database to validate ownership and fetch employee details
    db.query(
        "SELECT * FROM employees WHERE id = ? AND business_id = ? AND user_id = ?",
        [employeeId, businessId, userId],
        (err, results) => {
            if (err) {
                console.error("Error fetching employee:", err);
                return res.status(500).send("Error fetching employee.");
            }

            if (results.length === 0) {
                return res.status(404).send("Employee not found or unauthorized.");
            }

            res.json(results[0]); // Return the employee details
        }
    );
});
// Fetch all employees
app.get("/businesses/:id/employees", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from the token
    const { id: businessId } = req.params; // Business ID from the URL

    db.query(
        "SELECT * FROM employees WHERE business_id = ? AND user_id = ? AND disabled_at IS NULL",
        [businessId, userId],
        (err, results) => {
            if (err) {
                console.error("Error fetching employees:", err);
                return res.status(500).send("Error fetching employees.");
            }

            res.json(results);
        }
    );
});

//Fetch employee if salary is null, hourly employee api//
app.get("/businesses/:id/employees/hourly", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from the token
    const { id: businessId } = req.params; // Business ID from the URL

    db.query(
        "SELECT * FROM employees WHERE business_id = ? AND user_id = ? AND salary_amt IS NULL AND disabled = 0",
        [businessId, userId],
        (err, results) => {
            if (err) {
                console.error("Error fetching employees:", err);
                return res.status(500).send("Error fetching employees.");
            }

            res.json(results);
        }
    );
});

//fetch employee if hourly_amt is null, salary employee//
app.get("/businesses/:id/employees/salary", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from the token
    const { id: businessId } = req.params; // Business ID from the URL

    db.query(
        "SELECT * FROM employees WHERE business_id = ? AND user_id = ? AND hourly_amt IS NULL AND disabled = 0",
        [businessId, userId],
        (err, results) => {
            if (err) {
                console.error("Error fetching employees:", err);
                return res.status(500).send("Error fetching employees.");
            }

            res.json(results);
        }
    );
});



//Edit individual Employee//
app.put("/employees/:id", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { id: employeeId } = req.params;
    const {
        first_name,
        last_name,
        dob,
        ssn,
        filing_status,
        dependents,
        additional_fed_tax,
        additional_state_tax,
        e_st_add,
        e_suite,
        e_state,
        e_city,
        e_zip,
        salary_amt,
        hourly_amt,
    } = req.body;

    if (!first_name || !last_name || !dob || !ssn || !e_st_add || !e_state || !e_city || !e_zip) {
        return res.status(400).send("Missing required fields.");
    }

    if ((salary_amt && hourly_amt) || (!salary_amt && !hourly_amt)) {
        return res.status(400).send("You must provide either salary_amt or hourly_amt, but not both.");
    }

    db.query(
        `UPDATE employees 
         SET first_name = ?, last_name = ?, dob = ?, ssn = ?, filing_status = ?, dependents = ?, 
             additional_fed_tax = ?, additional_state_tax = ?, e_st_add = ?, e_suite = ?, 
             e_state = ?, e_city = ?, e_zip = ?, salary_amt = ?, hourly_amt = ?, updated_at = NOW() 
         WHERE id = ? AND user_id = ?`,
        [
            first_name,
            last_name,
            dob,
            ssn,
            filing_status,
            dependents || null,
            additional_fed_tax || null,
            additional_state_tax || null,
            e_st_add,
            e_suite || null,
            e_state,
            e_city,
            e_zip,
            salary_amt || null,
            hourly_amt || null,
            employeeId,
            userId,
        ],
        (err, result) => {
            if (err) {
                console.error("Error updating employee:", err);
                return res.status(500).send("Error updating employee.");
            }
            if (result.affectedRows === 0) {
                return res.status(404).send("Employee not found or unauthorized.");
            }
            res.send("Employee updated successfully.");
        }
    );
});





const rateLimiter = new Map(); // Store IP and request details
const RATE_LIMIT_WINDOW = 10 * 60 * 1000; // 10 minutes
const MAX_REQUESTS = 5; // Maximum requests per window

app.post("/forgot-password", (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).send("Email is required.");
    }

    // Capture the user's IP address
    const ipAddress = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    const currentTime = Date.now();
    const expiresAt = new Date(currentTime + 5 * 60 * 1000); // OTP valid for 5 minutes

    // Rate limiting logic
    if (!rateLimiter.has(ipAddress)) {
        // First request from this IP
        rateLimiter.set(ipAddress, { count: 1, firstRequest: currentTime });
    } else {
        const data = rateLimiter.get(ipAddress);
        const elapsed = currentTime - data.firstRequest;

        if (elapsed > RATE_LIMIT_WINDOW) {
            // Reset window after time has passed
            rateLimiter.set(ipAddress, { count: 1, firstRequest: currentTime });
        } else if (data.count >= MAX_REQUESTS) {
            // User has exceeded the request limit
            return res.status(429).send("Too many requests. Please try again later.");
        } else {
            // Increment request count
            data.count++;
        }
    }

    // Fetch the user by email
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).send("Server error.");
        }

        if (results.length === 0) {
            return res.status(401).send("Invalid credentials.");
        }

        const user = results[0];

        // Generate a 6-digit OTP
        const otp = generateOtp();

        // Insert OTP into the database
        db.query(
            "INSERT INTO otps (user_id, otp, ip_address, expires_at) VALUES (?, ?, ?, ?)",
            [user.id, otp, ipAddress, expiresAt],
            (otpErr) => {
                if (otpErr) {
                    console.error("Error inserting OTP:", otpErr);
                    return res.status(500).send("Error generating OTP.");
                }

                // Log OTP for testing purposes (to be replaced with email/SMS in production)
                console.log(`Generated OTP for ${user.email}: ${otp} (IP: ${ipAddress})`);

                // Respond to the client
                res.status(200).send({
                    message: "OTP generated. Check terminal for OTP.",
                    userId: user.id,
                });
            }
        );
    });
});


// Optional: Clean up expired entries periodically to free memory
setInterval(() => {
    const currentTime = Date.now();
    for (const [ip, data] of rateLimiter.entries()) {
        if (currentTime - data.firstRequest > RATE_LIMIT_WINDOW) {
            rateLimiter.delete(ip);
        }
    }
}, RATE_LIMIT_WINDOW)




app.post("/reset-password", async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const ipAddress = req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    if (!email || !otp || !newPassword) {
        return res.status(400).send("Email, OTP, and new password are required.");
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Step 1: Validate user by email
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, userResults) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).send("Server error.");
        }
        if (userResults.length === 0) {
            return res.status(404).send("User not found.");
        }

        const user = userResults[0];
        const userId = user.id;

        // Step 2: Verify OTP
        db.query(
            "SELECT * FROM otps WHERE user_id = ? AND otp = ? AND ip_address = ? AND expires_at > NOW()",
            [userId, otp, ipAddress],
            (otpErr, otpResults) => {
                if (otpErr) {
                    console.error("Error fetching OTP:", otpErr);
                    return res.status(500).send("Server error while verifying OTP.");
                }
                if (otpResults.length === 0) {
                    return res.status(401).send("Invalid or expired OTP.");
                }


                // Step 4: Update the user's password
                db.query(
                    "UPDATE users SET password = ? WHERE id = ?",
                    [hashedPassword, userId],
                    (updateErr) => {
                        if (updateErr) {
                            console.error("Error updating password:", updateErr);
                            return res.status(500).send("Failed to update password.");
                        }

                        // Step 5: Delete OTP after successful reset
                        db.query(
                            "DELETE FROM otps WHERE user_id = ? AND ip_address = ?",
                            [userId, ipAddress],
                            (deleteErr) => {
                                if (deleteErr) {
                                    console.error("Error deleting OTP:", deleteErr);
                                    return res
                                        .status(500)
                                        .send("Password updated, but failed to delete OTP.");
                                }

                                // Success response
                                res.send("Password reset successful. You can now log in.");
                            }
                        );
                    }
                );
            }
        );
    });
});




app.post("/business/:businessId/previous-payroll", authenticateToken, (req, res) => {
    const { businessId } = req.params;
    const userId = req.user.id; // Extract the authenticated user ID
    const payrollData = req.body; // Data sent from the frontend

    // Iterate through payroll data and insert records for each entry
    payrollData.forEach((entry) => {
        const { employeeId, quarter, amount, fedTax, stateTax } = entry;
        const tableName = `payroll_q${quarter}_2024`;

        // Construct the query
        const query = `
            INSERT INTO ${tableName} (user_id, business_id, employee_id, amount, fed_tax, state_tax)
            VALUES (?, ?, ?, ?, ?, ?)
        `;

        // Execute the query with a callback
        db.query(
            query,
            [userId, businessId, employeeId, amount || null, fedTax || null, stateTax || null],
            (err, results) => {
                if (err) {
                    console.error(`Error saving payroll data for ${tableName}:`, err);
                    return res.status(500).send("Failed to save payroll data.");
                }
            }
        );
    });

    res.send("Payroll data saved successfully.");
});






app.post("/admin/payroll-tables/:year", authenticateToken, (req, res) => {
    const { year } = req.params;

    // Check if the user is an admin
    if (!req.user.isAdmin) {
        return res.status(403).send("Access denied.");
    }

    // Queries to create tables for the given year
    const tableQueries = [];
    for (let q = 1; q <= 4; q++) {
        tableQueries.push(`
            CREATE TABLE IF NOT EXISTS payroll_q${q}_${year} (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                business_id INT NOT NULL,
                employee_id INT NOT NULL,
                amount DECIMAL(10, 2),
                fed_tax DECIMAL(10, 2),
                state_tax DECIMAL(10, 2),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_user_id_q${q}_${year} FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                CONSTRAINT fk_business_id_q${q}_${year} FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
                CONSTRAINT fk_employee_id_q${q}_${year} FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );
        `);
    }

    // Execute queries to create tables
    Promise.all(tableQueries.map((query) => db.query(query)))
        .then(() => res.send(`Payroll tables for ${year} created successfully.`))
        .catch((err) => {
            console.error("Error creating tables:", err);
            res.status(500).send("Failed to create payroll tables.");
        });
});



app.get("/business/:businessId/payroll-data", authenticateToken, (req, res) => {
    const { businessId } = req.params;
    const userId = req.user.id; // Extract the authenticated user's ID
    const currentYear = new Date().getFullYear(); // Automatically get the current year
    const quarters = [1, 2, 3, 4]; // List of quarters to check
    let hasData = false;

    const checkQueries = quarters.map((quarter) => {
        const tableName = `payroll_q${quarter}_${currentYear}`;
        const query = `SELECT EXISTS(SELECT 1 FROM ${tableName} WHERE business_id = ? AND user_id = ?) AS hasData`;
        return new Promise((resolve, reject) => {
            db.query(query, [businessId, userId], (err, results) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(results[0].hasData);
                }
            });
        });
    });

    Promise.all(checkQueries)
        .then((results) => {
            hasData = results.some((data) => data === 1); // Check if any quarter has data
            res.json({ hasData });
        })
        .catch((err) => {
            console.error("Error checking payroll data:", err);
            res.status(500).send("Failed to check payroll data.");
        });
});

app.get("/business/:businessId/edit-previous-payroll", authenticateToken, (req, res) => {
    const { businessId } = req.params;
    const currentYear = new Date().getFullYear();
    const quarters = [1, 2, 3, 4]; // List of quarters
    const results = {}; // Store payroll data for all quarters

    const quarterQueries = quarters.map((quarter) => {
        const tableName = `payroll_q${quarter}_${currentYear}`;
        return new Promise((resolve, reject) => {
            db.query(
                `
    SELECT 
        CONCAT(e.first_name, ' ', e.last_name) AS employee_name,
        p.employee_id,
        p.amount,
        p.fed_tax,
        p.state_tax
    FROM ${tableName} p
    JOIN employees e ON p.employee_id = e.id
    WHERE p.business_id = ?
    `,
                [businessId],
                (err, rows) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({ quarter, data: rows });
                    }
                }
            );
        });
    });

    Promise.all(quarterQueries)
        .then((quarterData) => {
            quarterData.forEach(({ quarter, data }) => {
                results[`Q${quarter}`] = data;
            });

            res.json({
                businessId,
                year: currentYear,
                payroll: results,
            });
        })
        .catch((err) => {
            console.error("Error fetching payroll data:", err);
            res.status(500).send("Failed to fetch payroll data.");
        });
});




app.post("/business/:businessId/update-previous-payroll", authenticateToken, (req, res) => {
    const { businessId } = req.params; // Extract businessId from the URL
    const payrollData = req.body; // Data sent from the frontend
    const userId = req.user.id; // Extract user ID from the middleware

    console.log("User ID:", userId); // Debugging
    console.log("Business ID:", businessId); // Debugging
    console.log("Payroll Data:", payrollData); // Debugging

    // Update each record in the corresponding quarter table
    const updateQueries = payrollData.map((entry) => {
        const { employeeId, quarter, amount, fedTax, stateTax } = entry;
        const tableName = `payroll_q${quarter}_${new Date().getFullYear()}`; // Determine the table name

        return new Promise((resolve, reject) => {
            const query = `
                UPDATE ${tableName}
                SET amount = ?, fed_tax = ?, state_tax = ?
                WHERE user_id = ? AND business_id = ? AND employee_id = ?
            `;
            db.query(
                query,
                [amount || null, fedTax || null, stateTax || null, userId, businessId, employeeId],
                (err, results) => {
                    if (err) {
                        console.error(`Error updating table ${tableName}:`, err);
                        reject(err);
                    } else {
                        resolve(results);
                    }
                }
            );
        });
    });
    

    // Execute all update queries
    Promise.all(updateQueries)
        .then(() => res.send("Payroll data updated successfully."))
        .catch((err) => {
            console.error("Error updating payroll data:", err);
            res.status(500).send("Failed to update payroll data.");
        });
});

app.get("/businesses/:businessId/employees/:employeeId/deductions", authenticateToken, (req, res) => {
    const userId = req.user.id; // User ID from token
    const { employeeId } = req.params;

    db.query(
        `
        SELECT first_name, last_name, contrib_401k, healthcare, dental, vision, donation, garnishment
        FROM employees 
        WHERE id = ? AND user_id = ?
        `,
        [employeeId, userId],
        (err, results) => {
            if (err) {
                console.error("Error fetching deductions:", err);
                return res.status(500).send("Error fetching deductions.");
            }

            if (results.length === 0 ) {
                // Explicitly return null when no records are found
                return res.json(null);
            }

            res.json(results[0]); // Return the first record
        }
    );
});



app.get("/business/:businessId/employees/:employeeId/contributions", authenticateToken, (req, res) => {
    const { businessId, employeeId } = req.params;
    const userId = req.user.id; // Extract user ID from token

    const query = `
        SELECT 
    COALESCE(contrib_401k, 0.00) AS contrib_401k,
    COALESCE(healthcare, 0.00) AS healthcare,
    COALESCE(dental, 0.00) AS dental,
    COALESCE(vision, 0.00) AS vision,
    COALESCE(bonus, 0.00) AS bonus
FROM emp_contribs
WHERE business_id = ? AND employee_id = ? AND user_id = ?
    `;

    db.query(query, [businessId, employeeId, userId], (err, results) => {
        if (err) {
            console.error("Error fetching employee contributions:", err);
            return res.status(500).send("Failed to fetch employee contributions.");
        }

        res.json(results);
    });
});





app.put("/businesses/:businessId/employees/:employeeId/deductions", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract the authenticated user's ID
    const { businessId, employeeId } = req.params; // Extract businessId and employeeId from params
    const { contrib_401k, healthcare, dental, vision, donation, garnishment } = req.body; // Extract deduction fields from body

    if (!businessId || !employeeId) {
        return res.status(400).send("Missing required business_id or employee_id.");
    }

    // Use UPDATE query to modify existing record for the employee
    db.query(
        `
        UPDATE employees
        SET 
            contrib_401k = ?, 
            healthcare = ?, 
            dental = ?, 
            vision = ?, 
            donation = ?, 
            garnishment = ?
        WHERE id = ? AND business_id = ? AND user_id = ?
        `,
        [
            contrib_401k || null,
            healthcare || null,
            dental || null,
            vision || null,
            donation || null,
            garnishment || null,
            employeeId,
            businessId,
            userId,
        ],
        (err, result) => {
            if (err) {
                console.error("Error updating deductions:", err);
                return res.status(500).send("Error updating deductions.");
            }

            if (result.affectedRows === 0) {
                // No matching record found; let the client know
                return res.status(404).send("No deductions found for this employee to update.");
            }

            res.send("Preset deductions updated successfully.");
        }
    );
});


app.post("/businesses/:businessId/employees/:employeeId/deductions", authenticateToken, (req, res) => {
    const userId = req.user.id; // User ID from token
    const { businessId, employeeId } = req.params;
    const { contrib_401k, healthcare, dental, vision, donation, garnishment } = req.body;

    db.query(
        `
        UPDATE employees
        SET 
            contrib_401k = ?,
            healthcare = ?,
            dental = ?,
            vision = ?,
            donation = ?,
            garnishment = ?
        WHERE 
            id = ? AND 
            business_id = ? AND 
            user_id = ?
        `,
        [
            contrib_401k || null,
            healthcare || null,
            dental || null,
            vision || null,
            donation || null,
            garnishment || null,
            employeeId, // Using employeeId for the `id` column
            businessId,
            userId
        ],
        (err, result) => {
            if (err) {
                console.error("Error updating deductions:", err);
                return res.status(500).send("Error updating deductions.");
            }
            if (result.affectedRows === 0) {
                return res.status(404).send("Employee not found or no changes made.");
            }
            res.status(200).send("Deductions added successfully.");
        }
    );
});





app.put("/business/:businessId/set-pay-period", authenticateToken, (req, res) => {
    const { businessId } = req.params; // Extract business ID from URL
    const { startDate, endDate, payDate, frequency, frequencyEnteredOn } = req.body; // Data from the frontend
    const userId = req.user.id; // Extract user ID from the token


    console.log("Updating pay period for business:", businessId);
    console.log("Payload received:", { startDate, endDate, payDate, frequency, frequencyEnteredOn });

    const query = `
        UPDATE businesses 
        SET start_date = ?, 
            end_date = ?, 
            pay_date = ?, 
            frequency = ?, 
            frequency_enteredon = ? 
        WHERE owner_id = ? AND id = ?
    `;

    db.query(
        query,
        [startDate, endDate, payDate, frequency, frequencyEnteredOn, userId, businessId],
        (err,results) => {
            if (err) {
                console.error("Error updating business:", err);
                res.status(500).send("Failed to update pay period.");
                console.log("first error");
                return;
            }

            if (results.affectedRows === 0) {
                res.status(404).send("Business not found or unauthorized.");
                console.log("second motherfucker");
                return; // Stop further execution after sending a response
            }
            
            res.send("Pay period updated successfully.");
            console.log(results);
        }
        
    );
});



app.get("/business/:businessId/pay-period", authenticateToken, (req, res) => {
    const { businessId } = req.params;
    const userId = req.user.id;

    const query = `
        SELECT b_state, start_date, end_date, pay_date, frequency
        FROM businesses 
        WHERE id = ? AND owner_id = ?
    `;

    db.query(query, [businessId, userId], (err, results) => {
        if (err) {
            console.error("Error fetching pay period:", err);
            return res.status(500).send("Failed to fetch pay period.");
        }

        if (results.length === 0) {
            return res.status(404).send("No pay period found.");
        }

        res.json(results[0]);
    });
});


app.delete("/business/:businessId/pay-period", authenticateToken, (req, res) => {
    const { businessId } = req.params;
    const userId = req.user.id;

    const query = `
        UPDATE businesses 
        SET start_date = NULL, end_date = NULL, pay_date = NULL, frequency = NULL, frequency_enteredon = NULL 
        WHERE id = ? AND owner_id = ?
    `;

    db.query(query, [businessId, userId], (err, result) => {
        if (err) {
            console.error("Error deleting pay period:", err);
            return res.status(500).send("Failed to delete pay period.");
        }

        if (result.affectedRows === 0) {
            return res.status(404).send("Pay period not found or unauthorized.");
        }

        res.send("Pay period deleted successfully.");
    });
});






app.post("/payroll/calculate", authenticateToken, async (req, res) => {
    if (!Array.isArray(req.body)) {
        return res.status(400).send("Payload must be an array of records.");
    }

    const payrollData = req.body;
    const results = [];
    const errors = [];

    const standardDeductions = {
        Single: 13850,
        Married: 27700,
        "Head of Household": 20800,
    };

    const calculateFederalTax = async (adjustedIncome, filing_status) => {
        const taxBrackets = await new Promise((resolve, reject) => {
            db.query(
                `SELECT tax_rate, income_min, income_max 
                 FROM fedtaxrates 
                 WHERE filing_status = ? 
                 ORDER BY income_min ASC`,
                [filing_status],
                (err, results) => {
                    if (err) {
                        return reject(err);
                    }
                    resolve(results);
                }
            );
        });

        let federalTax = 0;
        let remainingIncome = adjustedIncome;

        for (const bracket of taxBrackets) {
            const { tax_rate, income_min, income_max } = bracket;

            if (remainingIncome <= 0) break;

            const lowerLimit = parseFloat(income_min);
            const upperLimit = income_max ? parseFloat(income_max) : Infinity;

            const taxableIncome = Math.min(remainingIncome, upperLimit - lowerLimit);
            federalTax += taxableIncome * (parseFloat(tax_rate) / 100);

            remainingIncome -= taxableIncome;

            console.log(
                `Federal Bracket: ${tax_rate}% | Lower: ${lowerLimit} | Upper: ${upperLimit} | Taxable: ${taxableIncome} | Cumulative Tax: ${federalTax}`
            );
        }

        return Math.max(0, federalTax);
    };




 


    const calculateStateTax = async (
        grossPay,
        frequency,
        employeeState,
        businessState,
        dependents,
        filingStatus
    ) => {
        try {
            console.log("Starting calculateStateTax...");
            const payrollFrequencyMultiplier = {
                weekly: 52,
                biweekly: 26,
                semimonthly: 24,
                monthly: 12,
            }[frequency.toLowerCase()];
    
            if (!payrollFrequencyMultiplier) {
                throw new Error(`Invalid frequency: ${frequency}`);
            }
    
            const annualGrossPay = grossPay * payrollFrequencyMultiplier;
    
            if (employeeState === businessState) {
                const stateTax = await calculateSingleStateTax(
                    annualGrossPay,
                    payrollFrequencyMultiplier,
                    employeeState,
                    dependents,
                    filingStatus
                );
                return { stateTax, workTax: 0 };
            }

            // 2. Check for reciprocity
                const reciprocityApplies = await checkReciprocity(employeeState, businessState);
            if (reciprocityApplies) {
                const stateTax = await calculateSingleStateTax(annualGrossPay, payrollFrequencyMultiplier, employeeState, dependents, filingStatus);
                return { stateTax, workTax: 0 };
            }
    
            // Multi-state logic
            const employeeStateData = await fetchStateTaxData(employeeState);
            const businessStateData = await fetchStateTaxData(businessState);
    
            const workStateTax = await calculateSingleStateTax(
                annualGrossPay,
                payrollFrequencyMultiplier,
                businessState,
                dependents,
                filingStatus
            );
    
            let residentStateTax = await calculateSingleStateTax(
                annualGrossPay,
                payrollFrequencyMultiplier,
                employeeState,
                dependents,
                filingStatus
            );
    
            if (employeeStateData.credits_out_of_state) {
                const maxCredit = workStateTax * employeeStateData.credit_limit;
                residentStateTax = Math.max(0, residentStateTax - maxCredit);
                console.log(residentStateTax);
                console.log(employeeStateData.credit_limit);
            }
    
            return { stateTax: residentStateTax, workTax: workStateTax };
        } catch (error) {
            console.error("Error in calculateStateTax:", error);
            return { stateTax: 0, workTax: 0 }; // Ensure valid defaults
        }
    };
    
    const checkReciprocity = async (residentState, workState) => {
        console.log(`Checking reciprocity between ${residentState} and ${workState}...`);
        return new Promise((resolve, reject) => {
            db.query(
                `SELECT reciprocity_states 
                 FROM auth_app.us_st 
                 WHERE st_code = ?`,
                [residentState],
                (err, results) => {
                    if (err) return reject(err);
                    const reciprocityStates = results[0]?.reciprocity_states || null;
                    if (reciprocityStates) {
                        const statesList = reciprocityStates.split(',');
                        resolve(statesList.includes(workState));
                    } else {
                        resolve(false);
                    }
                }
            );
        });
    };
    
    


    // Fetch state tax data
    const fetchStateTaxData = async (stateCode) => {
        console.log(`Fetching tax data for state: ${stateCode}`);
        return new Promise((resolve, reject) => {
            db.query(
                `SELECT st_name, tax_calculation_type, standard_deduction_single, 
                        standard_deduction_married, exemption_amount, state_tax_rate, 
                        flat_tax, reciprocity_states, credits_out_of_state, credit_limit
                 FROM auth_app.us_st
                 WHERE st_code = ?`,
                [stateCode],
                (err, results) => {
                    if (err) return reject(err);
                    if (!results[0]) return reject(new Error(`No tax data found for state: ${stateCode}`));
                    resolve(results[0]);
                }
            );
        });
    };
    
    // Calculate single-state tax
    const calculateSingleStateTax = async (
        annualGrossPay,
        payrollFrequencyMultiplier,
        stateCode,
        dependents,
        filingStatus
    ) => {
        const stateTaxData = await fetchStateTaxData(stateCode);
    
        console.log("Calculating single-state tax...");
        const standardDeduction =
            filingStatus?.toLowerCase() === "married"
                ? parseFloat(stateTaxData.standard_deduction_married || 0)
                : parseFloat(stateTaxData.standard_deduction_single || 0);
    
        const dependentReduction = (dependents || 0) * parseFloat(stateTaxData.exemption_amount || 0);
        const totalDeductions = standardDeduction + dependentReduction;
    
        console.log(`Standard Deduction: ${standardDeduction}`);
        console.log(`Dependent Exemptions: ${dependentReduction}`);
        console.log(`Total Deductions: ${totalDeductions}`);
    
        const annualTaxableIncome = Math.max(0, annualGrossPay - totalDeductions);
        console.log(`Annual Taxable Income: ${annualTaxableIncome}`);
    
        let annualStateTax = 0;
    
        if (stateTaxData.tax_calculation_type === "flat_rate") {
            annualStateTax = annualTaxableIncome * parseFloat(stateTaxData.state_tax_rate || 0);
        } else if (stateTaxData.tax_calculation_type === "progressive") {
            console.log("Using progressive tax calculation...");
            const taxBrackets = await fetchProgressiveTaxBrackets(stateCode);
            annualStateTax = calculateProgressiveTax(annualTaxableIncome, taxBrackets);
        }
    
        console.log(`Annual State Tax: ${annualStateTax}`);
        const stateTaxPerPeriod = annualStateTax / payrollFrequencyMultiplier;
    
        console.log(`State Tax Per Period: ${stateTaxPerPeriod}`);
        return stateTaxPerPeriod;
    };
    
    // Fetch progressive tax brackets
    const fetchProgressiveTaxBrackets = async (stateCode) => {
        console.log(`Fetching progressive tax brackets for state: ${stateCode}`);
        return new Promise((resolve, reject) => {
            db.query(
                `SELECT bracket_min, bracket_max, bracket_rate
                 FROM auth_app.state_tax_brackets
                 WHERE st_code = ?
                 ORDER BY bracket_min ASC`,
                [stateCode],
                (err, results) => {
                    if (err) return reject(err);
                    resolve(results);
                }
            );
        });
    };
    
    // Calculate progressive tax
    const calculateProgressiveTax = (taxableIncome, taxBrackets) => {
        let remainingIncome = taxableIncome;
        let totalTax = 0;
    
        for (const { bracket_min, bracket_max, bracket_rate } of taxBrackets) {
            if (remainingIncome <= 0) break;
    
            const lowerLimit = parseFloat(bracket_min);
            const upperLimit = bracket_max ? parseFloat(bracket_max) : Infinity;
            const taxableAmount = Math.min(remainingIncome, upperLimit - lowerLimit);
    
            totalTax += taxableAmount * parseFloat(bracket_rate);
            remainingIncome -= taxableAmount;
        }
    
        return totalTax;
    };
    
    

    
   
    const calculateCityTaxes = async (grossPay, businessCity, employeeCity) => {
        const cityTaxData = await new Promise((resolve, reject) => {
            db.query(
                `SELECT city_name, res_inc_tax, non_res_inc_tax 
                 FROM city_all 
                 WHERE city_name IN (?, ?)`,
                [businessCity, employeeCity],
                (err, results) => {
                    if (err) {
                        return reject(err);
                    }
                    resolve(results);
                }
            );
        });

        const businessRates = cityTaxData.find((c) => c.city_name === businessCity) || {};
        const employeeRates = cityTaxData.find((c) => c.city_name === employeeCity) || {};

        const businessTaxRate = businessRates.non_res_inc_tax || 0;
        const employeeTaxRate = employeeRates.res_inc_tax || 0;

        let businessTax = 0;
        let employeeTax = 0;

        if (businessCity === employeeCity) {
            employeeTax = grossPay * (employeeTaxRate / 100);
        } else {
            businessTax = grossPay * (businessTaxRate / 100);
            employeeTax = grossPay * (employeeTaxRate / 100);
        }

        console.log({
            grossPay,
            businessCity,
            employeeCity,
            businessTaxRate,
            employeeTaxRate,
            businessTax,
            employeeTax,
        });

        return { businessTax, employeeTax };
    };

    for (const record of payrollData) {
        try {
            const {
                id,
                business_id,
                business_state,
                name,
                st_add,
                e_suite,
                e_zip,
                frequency,
                start_date,
                end_date,
                pay_date,
                hourly_rate,
                salary_amt,
                regularHours,
                overtimeHours,
                doubletimeHours,
                vacationHours,
                vacationPay,
                bonus,
                tips,
                reimbursement,
                cashAdvance,
                e_state,
                e_city,
                filing_status,
                dependents = 0,
                contrib_401k = 0,
                healthcare = 0,
                dental = 0,
                vision = 0,
                donation = 0,
                garnishment = 0,
                additional_fed_tax = 0,
                additional_state_tax = 0,
            } = record;



            if (hourly_rate && (regularHours === undefined || regularHours === null || regularHours === 0)) {
                return res.status(400).send(`Error: Missing or invalid 'regularHours' for hourly employee: ${name}`);
            }


                                // Fetch business data and check_no logic
                    const businessData = await new Promise((resolve, reject) => {
                        db.query(
                            `SELECT b_city, check_no, bankhaschanged 
                            FROM businesses 
                            WHERE id = ?`,
                            [business_id],
                            (err, results) => {
                                if (err) return reject(err);
                                resolve(results[0] || { b_city: "", check_no: null, bankhaschanged: false });
                            }
                        );
                    });

                    const businessCity = businessData.b_city || "";
                    let checkNo = businessData.check_no || null;
                    const bankHasChanged = businessData.bankhaschanged || false;

                    if (bankHasChanged) {
                        console.log("Bank info has changed. Using check_no from businesses table:", checkNo);

                        // Reset bankhaschanged to false
                        await new Promise((resolve, reject) => {
                            db.query(
                                `UPDATE businesses SET bankhaschanged = FALSE WHERE id = ?`,
                                [business_id],
                                (err) => {
                                    if (err) return reject(err);
                                    resolve();
                                }
                            );
                        });
                    } else {
                        // Get the last check_no from payroll table and increment it by 1
                        const lastCheckNo = await new Promise((resolve, reject) => {
                            db.query(
                                `SELECT check_no 
                                FROM payroll 
                                WHERE user_id = ? AND business_id = ? AND check_no IS NOT NULL
                                ORDER BY id DESC 
                                LIMIT 1`,
                                [req.user.id, business_id],
                                (err, results) => {
                                    if (err) return reject(err);
                                    resolve(results[0]?.check_no || null);
                                }
                            );
                        });

                        if (lastCheckNo) {
                            checkNo = parseInt(lastCheckNo, 10) + 1; // Increment the last check number by 1
                            console.log("Using last check_no from payroll +1:", checkNo);
                        } else {
                            console.log("No valid check_no in payroll. Defaulting to null.");
                            checkNo = null;
                        }
                    }

                    console.log("Final check_no to use:", checkNo);


        

            if (
                !id ||
                !business_id ||
                !business_state ||
                !name ||
                !frequency ||
                !start_date ||
                !end_date ||
                !pay_date ||
                !e_state ||
                !e_city ||
                !filing_status ||
                (!hourly_rate && !salary_amt) ||
                (hourly_rate && (regularHours === undefined || regularHours === null || regularHours === 0))
            ) {
                errors.push(`Missing required fields for record: ${name}`);
                continue;
            }

            // Calculate gross pay
            let grossPay = 0;
            let regPay = 0;
            let otPay = 0;
            let dtPay = 0;
            let vtPay = 0;
            if (hourly_rate) {
                const regularPay = (regularHours ?? 0) * (hourly_rate ?? 0);
                const ot_rate = hourly_rate * 1.5;
                const overtimePay = (overtimeHours ?? 0) * ot_rate;
                const dt_rate = hourly_rate * 2;
                const doubletimePay = (doubletimeHours ?? 0) * dt_rate;
                const vacationTotal = (vacationHours ?? 0) * (hourly_rate ?? 0);

                grossPay = regularPay + overtimePay + doubletimePay + vacationTotal;
                regPay = regularPay;
                otPay = overtimePay;
                dtPay = doubletimePay;
                vtPay = vacationTotal;
            } else if (salary_amt) {
                grossPay = salary_amt;
            }

            grossPay += (bonus ?? 0) + (tips ?? 0) + (vacationPay ?? 0);

            const annualGrossPay =
                frequency.toLowerCase() === "weekly"
                    ? grossPay * 52
                    : frequency.toLowerCase() === "biweekly"
                    ? grossPay * 26
                    : frequency.toLowerCase() === "semimonthly"
                    ? grossPay * 24
                    : grossPay * 12;

            const dependentReduction = dependents * 2300;
            const standardDeduction = standardDeductions[filing_status] || 0;

            const adjustedAnnualIncome =
                annualGrossPay - dependentReduction - standardDeduction;

            console.log({
                grossPay,
                annualGrossPay,
                dependentReduction,
                standardDeduction,
                adjustedAnnualIncome,
            });

            // Calculate annual federal tax
            const federalTaxAnnual = await calculateFederalTax(adjustedAnnualIncome, filing_status);

            // Adjust federal tax to match the payroll period
            const federalTax =
                frequency.toLowerCase() === "weekly"
                    ? federalTaxAnnual / 52
                    : frequency.toLowerCase() === "biweekly"
                    ? federalTaxAnnual / 26
                    : frequency.toLowerCase() === "semimonthly"
                    ? federalTaxAnnual / 24
                    : federalTaxAnnual / 12;

            console.log({ adjustedIncome: adjustedAnnualIncome, filing_status, federalTax });

            const {stateTax, workTax} = await calculateStateTax(
                grossPay,
                frequency,
                e_state,
                business_state,
                dependents,
                filing_status
            );

            const { businessTax, employeeTax } = await calculateCityTaxes(
                grossPay,
                businessCity,
                e_city
            );

            const fedSS = grossPay * 0.062;
            const fedMed = grossPay * 0.0145;




            const totalDeductions =
                federalTax +
                (stateTax || 0) +
                (workTax || 0) +
                businessTax +
                employeeTax +
                fedSS +
                fedMed +
                (cashAdvance ?? 0) +
                Number(contrib_401k ?? 0) +
                Number(healthcare ?? 0) +
                Number(dental ?? 0) +
                Number(vision ?? 0) +
                Number(donation ?? 0) +
                Number(garnishment ?? 0) +
                Number(additional_fed_tax ?? 0) +
                Number(additional_state_tax ?? 0);

            const netPay = grossPay - totalDeductions + reimbursement;
            

            // Insert Data into Payroll
            const values = [
                req.user.id,
                business_id,
                business_state,
                id,
                name,
                frequency,
                new Date(start_date).toISOString().split("T")[0],
                new Date(end_date).toISOString().split("T")[0],
                new Date(pay_date).toISOString().split("T")[0],
                hourly_rate ?? null,
                regularHours ?? null,
                salary_amt ?? null,
                regPay ?? null,
                hourly_rate ? hourly_rate * 1.5 : null,
                overtimeHours ?? null,
                otPay ?? null,
                hourly_rate ? hourly_rate * 2 : null,
                doubletimeHours ?? null,
                dtPay ?? null,
                grossPay,
                fedSS,
                fedMed,
                cashAdvance ?? null,
                contrib_401k ?? null,
                healthcare ?? null,
                dental ?? null,
                vision ?? null,
                donation ?? null,
                garnishment ?? null,
                bonus ?? null,
                tips ?? null,
                reimbursement ?? null,
                federalTax,
                netPay,
                e_state,
                e_city,
                filing_status,
                dependents ?? null,
                additional_fed_tax ?? null,
                additional_state_tax ?? null,
                stateTax,
                workTax ?? null,
                businessCity,
                businessTax ?? null,
                e_city,
                employeeTax ?? null,
                checkNo ?? null,
                st_add,
                e_suite ?? null,
                e_zip,
                vacationHours ?? null,
                vtPay ?? null,
                vacationPay ?? null,
            ];


            console.log("Query values:", values);
           

            const insertQuery = `
                INSERT INTO payroll (
                    user_id, business_id, business_state, employee_id, name, frequency, start_date, end_date, pay_date, hourly_rate, regularHours,salarypay, regularPay,
                    ot_rate, overtimeHours, overtimePay, dt_rate, doubletimeHours, doubletimePay, grossPay, fed_ss, fed_med,
                    cashAdvance, contrib_401k, healthcare, dental, vision, donation, garnishment, bonus, tips, reimbursement, fed_tax, net_pay,
                    state, city, filing_status, dependents, additional_fed_tax, additional_state_tax, state_tax, work_state_tax, local_city1, local_citytax1, local_city2, local_citytax2,
                    check_no, e_st_add, e_suite, e_zip, vacation_hours, vacation_total, vacation_pay
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            await new Promise((resolve, reject) => {
                db.query(insertQuery, values, (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });

            results.push({ name, status: "Success" });
        } catch (error) {
            console.error(`Error for record ${record.name}:`, error);
            errors.push(`Error for ${record.name}: ${error.message}`);
        }
    }

    // Send consolidated response
    res.status(200).send({ success: results, errors });
});



app.get("/payroll/view/:businessId", authenticateToken, (req, res) => {
    const businessId = parseInt(req.params.businessId, 10); 
    const userId = req.user.id;

    const query = `
        SELECT id, name, grosspay, net_pay, end_date
        FROM payroll
        WHERE business_id = ? AND user_id = ?
    `;

    db.query(query, [businessId, userId], (err, results) => {
        if (err) {
            console.error("Database error:", err.message);
            return res.status(500).json({ error: "Database error. Please try again later." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "No payroll data found." });
        }

        res.json(results);
    });
});



app.post("/payroll/delete", authenticateToken, (req, res) => {
    const { ids } = req.body; // Array of IDs to delete

    if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: "Invalid or empty IDs array." });
    }

    const placeholders = ids.map(() => "?").join(", ");
    const query = `
        DELETE FROM payroll
        WHERE id IN (${placeholders})
    `;
    console.log("deleted records");

    db.query(query, ids, (err, result) => {
        if (err) {
            console.error("Error deleting payroll records:", err);
            return res.status(500).json({ error: "Database error. Failed to delete records." });
        }

        res.json({
            success: true,
            message: `${result.affectedRows} records deleted successfully.`,
        });
    });
});












app.get("/payroll/recent/:businessId", authenticateToken, (req, res) => {
    const businessId = parseInt(req.params.businessId, 10);
    const userId = req.user.id;

    const query = `
        SELECT id, name, grosspay, net_pay, start_date, end_date, pay_date, frequency
        FROM payroll
        WHERE business_id = ? AND user_id = ? 
        AND end_date = (SELECT MAX(end_date) FROM payroll WHERE business_id = ? AND user_id = ?)
        AND start_date = (SELECT MAX(start_date) FROM payroll WHERE business_id = ? AND user_id = ?)
        AND pay_date = (SELECT MAX(pay_date) FROM payroll WHERE business_id = ? AND user_id = ?)
    `;

    db.query(query, [businessId, userId, businessId, userId, businessId, userId, businessId, userId], (err, results) => {
        if (err) {
            console.error("Error fetching recent payroll data:", err);
            return res.status(500).json({ error: "Failed to fetch payroll data." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "No payroll records found for the most recent pay period." });
        }

        res.json(results);
    });
});

app.get("/payroll/periods/:businessId", authenticateToken, (req, res) => {
    const businessId = parseInt(req.params.businessId, 10);
    const userId = req.user.id;

    const query = `
        SELECT DISTINCT start_date, end_date, pay_date, frequency
        FROM payroll
        WHERE business_id = ? AND user_id = ?
        ORDER BY end_date DESC
    `;

    db.query(query, [businessId, userId], (err, results) => {
        if (err) {
            console.error("Error fetching payroll periods:", err);
            return res.status(500).json({ error: "Failed to fetch payroll periods." });
        }

        res.json(results);
    });
});


app.get("/payroll/next/:businessId", authenticateToken, (req, res) => {
    const businessId = parseInt(req.params.businessId, 10);
    const userId = req.user.id;

    const query = `
        SELECT business_state, start_date, end_date, pay_date, frequency
        FROM payroll
        WHERE business_id = ? AND user_id = ?
        AND end_date = (SELECT MAX(end_date) FROM payroll WHERE business_id = ? AND user_id = ?)
        AND start_date = (SELECT MAX(start_date) FROM payroll WHERE business_id = ? AND user_id = ?)
        AND pay_date = (SELECT MAX(pay_date) FROM payroll WHERE business_id = ? AND user_id = ?)
    `;

    db.query(query, [businessId, userId, businessId, userId, businessId, userId, businessId, userId], (err, results) => {
        if (err) {
            console.error("Error fetching recent payroll data:", err);
            return res.status(500).json({ error: "Failed to fetch payroll data." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "No payroll records found for the most recent pay period." });
        }

        const recentPayroll = results[0];
        const { start_date, end_date, pay_date, frequency, business_state } = recentPayroll;

        // Convert string dates to Date objects
        const startDate = new Date(start_date);
        const endDate = new Date(end_date);
        const payDate = new Date(pay_date);

        let newStartDate, newEndDate, newPayDate;

        switch (frequency.toLowerCase()) {
            case "weekly":
                newStartDate = new Date(startDate);
                newStartDate.setDate(newStartDate.getDate() + 7);

                newEndDate = new Date(endDate);
                newEndDate.setDate(newEndDate.getDate() + 7);

                newPayDate = new Date(payDate);
                newPayDate.setDate(newPayDate.getDate() + 7);
                break;

            case "biweekly":
                newStartDate = new Date(startDate);
                newStartDate.setDate(newStartDate.getDate() + 14);

                newEndDate = new Date(endDate);
                newEndDate.setDate(newEndDate.getDate() + 14);

                newPayDate = new Date(payDate);
                newPayDate.setDate(newPayDate.getDate() + 14);
                break;

            case "semimonthly":
                const startDay = startDate.getDate();
                const is16th = startDay === 16;

                if (is16th) {
                    newStartDate = new Date(startDate);
                    newStartDate.setMonth(startDate.getMonth() + 1); // Move to next month
                    newStartDate.setDate(1); // Set to 1st of the month
                } else {
                    newStartDate = new Date(startDate);
                    newStartDate.setDate(16); // Set to 16th of the same month
                }

                const endDay = endDate.getDate();
                const isEndOfMonth = endDay !== 15 && endDate.getDate() === new Date(endDate.getFullYear(), endDate.getMonth() + 1, 0).getDate();

                if (isEndOfMonth) {
                    newEndDate = new Date(endDate);
                    newEndDate.setMonth(endDate.getMonth() + 1); // Move to next month
                    newEndDate.setDate(15); // Set to 15th of the next month
                } else {
                    newEndDate = new Date(endDate);
                    newEndDate.setDate(new Date(endDate.getFullYear(), endDate.getMonth() + 1, 0).getDate()); // Set to end of the month
                }

                const payDateDiff = (payDate - endDate) / (1000 * 60 * 60 * 24); // Calculate days difference
                newPayDate = new Date(newEndDate);
                newPayDate.setDate(newPayDate.getDate() + payDateDiff); // Apply the same difference
                break;

            case "monthly":
                newStartDate = new Date(startDate);
                newStartDate.setMonth(newStartDate.getMonth() + 1);
                newStartDate.setDate(1); // 1st of next month

                newEndDate = new Date(newStartDate);
                newEndDate.setMonth(newEndDate.getMonth() + 1);
                newEndDate.setDate(0); // End of next month

                const monthlyPayDateDiff = (payDate - endDate) / (1000 * 60 * 60 * 24); // Calculate days difference
                newPayDate = new Date(newEndDate);
                newPayDate.setDate(newPayDate.getDate() + monthlyPayDateDiff); // Apply the same difference
                break;

            default:
                return res.status(400).json({ error: `Unsupported frequency: ${frequency}` });
        }

        // Respond with the calculated dates and frequency
        res.json({
            business_state,
            start_date: newStartDate.toLocaleDateString().split("T")[0], // Format as YYYY-MM-DD
            end_date: newEndDate.toLocaleDateString().split("T")[0],
            pay_date: newPayDate.toLocaleDateString().split("T")[0],
            frequency,
        });
    });
});




app.get("/payroll/records/:businessId", authenticateToken, (req, res) => {
    const businessId = parseInt(req.params.businessId, 10);
    const userId = req.user.id;
    const { start_date, end_date, pay_date } = req.query;


    const query = `
        SELECT id, name, grosspay, net_pay
        FROM payroll
        WHERE business_id = ? AND user_id = ?
        AND start_date = ? AND end_date = ? AND pay_date = ?
    `;

    db.query(query, [businessId, userId, start_date, end_date, pay_date], (err, results) => {
        if (err) {
            console.error("Error fetching payroll records:", err);
            return res.status(500).json({ error: "Failed to fetch payroll records." });
        }
        console.log(pay_date);
        console.log(results);

        res.json(results);
    });
});


app.get("/payroll/record/:businessId/:id", authenticateToken, (req, res) => {
    const { businessId, id } = req.params;
    const userId = req.user?.id;

    console.log("Params:", req.params);
    console.log("User ID:", userId);

    if (!businessId || !id || !userId) {
        return res.status(400).json({ error: "Invalid parameters." });
    }

    const query = `
        SELECT id, employee_id, name, hourly_rate, start_date, end_date, pay_date, frequency, grosspay, vacation_hours, vacation_pay, net_pay, regularhours, overtimehours, doubletimehours, 
               cashadvance, bonus, tips, reimbursement
        FROM payroll
        WHERE business_id = ? AND id = ? AND user_id = ?
    `;

    db.query(query, [businessId, id, userId], (err, results) => {
        if (err) {
            console.error("Error fetching payroll record:", err);
            return res.status(500).json({ error: "Failed to fetch payroll record." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "No payroll record found." });
        }

        res.json(results[0]); // Return the relevant row
    });
});





app.put("/payroll/record/:businessId/:id", authenticateToken, async (req, res) => {
    const { businessId, id } = req.params;
    const userId = req.user.id;

    console.log("Params:", { businessId, id });
    console.log("User ID:", userId);


        const standardDeductions = {
            Single: 13850,
            Married: 27700,
            "Head of Household": 20800,
        };        


        const calculateFederalTax = async (adjustedIncome, filing_status) => {
            const taxBrackets = await new Promise((resolve, reject) => {
                db.query(
                    `SELECT tax_rate, income_min, income_max 
                     FROM fedtaxrates 
                     WHERE filing_status = ? 
                     ORDER BY income_min ASC`,
                    [filing_status],
                    (err, results) => {
                        if (err) {
                            return reject(err);
                        }
                        resolve(results);
                    }
                );
            });
    
            let federalTax = 0;
            let remainingIncome = adjustedIncome;
    
            for (const bracket of taxBrackets) {
                const { tax_rate, income_min, income_max } = bracket;
    
                if (remainingIncome <= 0) break;
    
                const lowerLimit = parseFloat(income_min);
                const upperLimit = income_max ? parseFloat(income_max) : Infinity;
    
                const taxableIncome = Math.min(remainingIncome, upperLimit - lowerLimit);
                federalTax += taxableIncome * (parseFloat(tax_rate) / 100);
    
                remainingIncome -= taxableIncome;
    
                console.log(
                    `Federal Bracket: ${tax_rate}% | Lower: ${lowerLimit} | Upper: ${upperLimit} | Taxable: ${taxableIncome} | Cumulative Tax: ${federalTax}`
                );
            }
    
            return Math.max(0, federalTax);
        };





        const calculateStateTax = async (
            grossPay,
            frequency,
            employeeState,
            businessState,
            dependents,
            filingStatus
        ) => {
            try {
                console.log("Starting calculateStateTax...");
                const payrollFrequencyMultiplier = {
                    weekly: 52,
                    biweekly: 26,
                    semimonthly: 24,
                    monthly: 12,
                }[frequency.toLowerCase()];
        
                if (!payrollFrequencyMultiplier) {
                    throw new Error(`Invalid frequency: ${frequency}`);
                }
        
                const annualGrossPay = grossPay * payrollFrequencyMultiplier;
        
                if (employeeState === businessState) {
                    const stateTax = await calculateSingleStateTax(
                        annualGrossPay,
                        payrollFrequencyMultiplier,
                        employeeState,
                        dependents,
                        filingStatus
                    );
                    return { stateTax, workTax: 0 };
                }
    
                // 2. Check for reciprocity
                    const reciprocityApplies = await checkReciprocity(employeeState, businessState);
                if (reciprocityApplies) {
                    const stateTax = await calculateSingleStateTax(annualGrossPay, payrollFrequencyMultiplier, employeeState, dependents, filingStatus);
                    return { stateTax, workTax: 0 };
                }
        
                // Multi-state logic
                const employeeStateData = await fetchStateTaxData(employeeState);
                const businessStateData = await fetchStateTaxData(businessState);
        
                const workStateTax = await calculateSingleStateTax(
                    annualGrossPay,
                    payrollFrequencyMultiplier,
                    businessState,
                    dependents,
                    filingStatus
                );
        
                let residentStateTax = await calculateSingleStateTax(
                    annualGrossPay,
                    payrollFrequencyMultiplier,
                    employeeState,
                    dependents,
                    filingStatus
                );
        
                if (employeeStateData.credits_out_of_state) {
                    const maxCredit = workStateTax * employeeStateData.credit_limit;
                    residentStateTax = Math.max(0, residentStateTax - maxCredit);
                    console.log(residentStateTax);
                    console.log(employeeStateData.credit_limit);
                }
        
                return { stateTax: residentStateTax, workTax: workStateTax };
            } catch (error) {
                console.error("Error in calculateStateTax:", error);
                return { stateTax: 0, workTax: 0 }; // Ensure valid defaults
            }
        };
        
        const checkReciprocity = async (residentState, workState) => {
            console.log(`Checking reciprocity between ${residentState} and ${workState}...`);
            return new Promise((resolve, reject) => {
                db.query(
                    `SELECT reciprocity_states 
                     FROM auth_app.us_st 
                     WHERE st_code = ?`,
                    [residentState],
                    (err, results) => {
                        if (err) return reject(err);
                        const reciprocityStates = results[0]?.reciprocity_states || null;
                        if (reciprocityStates) {
                            const statesList = reciprocityStates.split(',');
                            resolve(statesList.includes(workState));
                        } else {
                            resolve(false);
                        }
                    }
                );
            });
        };
        
        
    
    
        // Fetch state tax data
        const fetchStateTaxData = async (stateCode) => {
            console.log(`Fetching tax data for state: ${stateCode}`);
            return new Promise((resolve, reject) => {
                db.query(
                    `SELECT st_name, tax_calculation_type, standard_deduction_single, 
                            standard_deduction_married, exemption_amount, state_tax_rate, 
                            flat_tax, reciprocity_states, credits_out_of_state, credit_limit
                     FROM auth_app.us_st
                     WHERE st_code = ?`,
                    [stateCode],
                    (err, results) => {
                        if (err) return reject(err);
                        if (!results[0]) return reject(new Error(`No tax data found for state: ${stateCode}`));
                        resolve(results[0]);
                    }
                );
            });
        };
        
        // Calculate single-state tax
        const calculateSingleStateTax = async (
            annualGrossPay,
            payrollFrequencyMultiplier,
            stateCode,
            dependents,
            filingStatus
        ) => {
            const stateTaxData = await fetchStateTaxData(stateCode);
        
            console.log("Calculating single-state tax...");
            const standardDeduction =
                filingStatus?.toLowerCase() === "married"
                    ? parseFloat(stateTaxData.standard_deduction_married || 0)
                    : parseFloat(stateTaxData.standard_deduction_single || 0);
        
            const dependentReduction = (dependents || 0) * parseFloat(stateTaxData.exemption_amount || 0);
            const totalDeductions = standardDeduction + dependentReduction;
        
            console.log(`Standard Deduction: ${standardDeduction}`);
            console.log(`Dependent Exemptions: ${dependentReduction}`);
            console.log(`Total Deductions: ${totalDeductions}`);
        
            const annualTaxableIncome = Math.max(0, annualGrossPay - totalDeductions);
            console.log(`Annual Taxable Income: ${annualTaxableIncome}`);
        
            let annualStateTax = 0;
        
            if (stateTaxData.tax_calculation_type === "flat_rate") {
                annualStateTax = annualTaxableIncome * parseFloat(stateTaxData.state_tax_rate || 0);
            } else if (stateTaxData.tax_calculation_type === "progressive") {
                console.log("Using progressive tax calculation...");
                const taxBrackets = await fetchProgressiveTaxBrackets(stateCode);
                annualStateTax = calculateProgressiveTax(annualTaxableIncome, taxBrackets);
            }
        
            console.log(`Annual State Tax: ${annualStateTax}`);
            const stateTaxPerPeriod = annualStateTax / payrollFrequencyMultiplier;
        
            console.log(`State Tax Per Period: ${stateTaxPerPeriod}`);
            return stateTaxPerPeriod;
        };
        
        // Fetch progressive tax brackets
        const fetchProgressiveTaxBrackets = async (stateCode) => {
            console.log(`Fetching progressive tax brackets for state: ${stateCode}`);
            return new Promise((resolve, reject) => {
                db.query(
                    `SELECT bracket_min, bracket_max, bracket_rate
                     FROM auth_app.state_tax_brackets
                     WHERE st_code = ?
                     ORDER BY bracket_min ASC`,
                    [stateCode],
                    (err, results) => {
                        if (err) return reject(err);
                        resolve(results);
                    }
                );
            });
        };
        
        // Calculate progressive tax
        const calculateProgressiveTax = (taxableIncome, taxBrackets) => {
            let remainingIncome = taxableIncome;
            let totalTax = 0;
        
            for (const { bracket_min, bracket_max, bracket_rate } of taxBrackets) {
                if (remainingIncome <= 0) break;
        
                const lowerLimit = parseFloat(bracket_min);
                const upperLimit = bracket_max ? parseFloat(bracket_max) : Infinity;
                const taxableAmount = Math.min(remainingIncome, upperLimit - lowerLimit);
        
                totalTax += taxableAmount * parseFloat(bracket_rate);
                remainingIncome -= taxableAmount;
            }
        
            return totalTax;
        };



        const calculateCityTaxes = async (grossPay, businessCity, employeeCity) => {
            const cityTaxData = await new Promise((resolve, reject) => {
                db.query(
                    `SELECT city_name, res_inc_tax, non_res_inc_tax 
                     FROM city_all 
                     WHERE city_name IN (?, ?)`,
                    [businessCity, employeeCity],
                    (err, results) => {
                        if (err) {
                            return reject(err);
                        }
                        resolve(results);
                    }
                );
            });
    
            const businessRates = cityTaxData.find((c) => c.city_name === businessCity) || {};
            const employeeRates = cityTaxData.find((c) => c.city_name === employeeCity) || {};
    
            const businessTaxRate = businessRates.non_res_inc_tax || 0;
            const employeeTaxRate = employeeRates.res_inc_tax || 0;
    
            let businessTax = 0;
            let employeeTax = 0;
    
            if (businessCity === employeeCity) {
                employeeTax = grossPay * (employeeTaxRate / 100);
            } else {
                businessTax = grossPay * (businessTaxRate / 100);
                employeeTax = grossPay * (employeeTaxRate / 100);
            }
    
            console.log({
                grossPay,
                businessCity,
                employeeCity,
                businessTaxRate,
                employeeTaxRate,
                businessTax,
                employeeTax,
            });
    
            return { businessTax, employeeTax };
        };



        
    try {
        // Fetch business city and state
        const businessQuery = `
            SELECT b_city, b_state 
            FROM businesses 
            WHERE id = ?
        `;
        const [business] = await new Promise((resolve, reject) => {
            db.query(businessQuery, [businessId], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        if (!business) {
            console.error("Business not found.");
            return res.status(404).json({ error: "Business not found." });
        }

        const { b_city, b_state } = business;
        console.log("Business Data:", { b_city, b_state });



        // Parse numeric fields to avoid NaN values
        const data = req.body;

        const employeeQuery = `
            SELECT e_city, e_state, filing_status, salary_amt, hourly_amt, dependents, contrib_401k, healthcare, dental, vision, donation, garnishment  
            FROM employees 
            WHERE id = ?
        `;
        const [employee] = await new Promise((resolve, reject) => {
            db.query(employeeQuery, [data.employee_id], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        if (!employee) {
            console.error("Employee not found.");
            return res.status(404).json({ error: "Employee not found." });
        }

        const { e_city, e_state, filing_status, salary_amt, hourly_amt, dependents, contrib_401k, healthcare, dental, vision, donation, garnishment } = employee;
        console.log("Employee Data:", {  e_city, e_state, filing_status, salary_amt, hourly_amt, dependents, contrib_401k, healthcare, dental, vision, donation, garnishment });



        // Adjust federal tax to match the payroll period
        const Salary =
        data.frequency.toLowerCase() === "weekly"
        ? salary_amt / 52
        : data.frequency.toLowerCase() === "biweekly"
        ? salary_amt / 26
        : data.frequency.toLowerCase() === "semimonthly"
        ? salary_amt / 24
        : salary_amt / 12;

        console.log({ Salary });



        const parsedData = {
            hourly_rate: parseFloat(hourly_amt) || 0,
            dependents: parseFloat(dependents) || 0,
            regularhours: parseFloat(data.regularhours) || 0,
            overtimehours: parseFloat(data.overtimehours) || 0,
            doubletimehours: parseFloat(data.doubletimehours) || 0,
            vacationhours: parseFloat(data.vacation_hours) || 0,
            vacationpay: parseFloat(data.vacation_pay) || 0,
            cashadvance: parseFloat(data.cashadvance) || 0,
            bonus: parseFloat(data.bonus) || 0,
            tips: parseFloat(data.tips) || 0,
            reimbursement: parseFloat(data.reimbursement) || 0,
            contrib_401k: parseFloat(contrib_401k) || 0,
            healthcare: parseFloat(healthcare) || 0,
            dental: parseFloat(dental) || 0,
            vision: parseFloat(vision) || 0,
            donation: parseFloat(donation) || 0,
            garnishment: parseFloat(garnishment) || 0,
            salary_amt: parseFloat(Salary) || 0,
        };

        console.log("Parsed Data:", parsedData);


        

        // Calculate grosspay
        const otRate = parsedData.hourly_rate * 1.5;
        const dtRate = parsedData.hourly_rate * 2;
        const regularPay = parsedData.regularhours * parsedData.hourly_rate;
        const overtimePay = parsedData.overtimehours * otRate;
        const doubletimePay = parsedData.doubletimehours * dtRate;
        const vacationtotal = parsedData.vacationhours * parsedData.hourly_rate;

        // const grossPay =
        //     parsedData.salary_amt ||
        //     (regularPay + overtimePay + doubletimePay + parsedData.bonus + parsedData.tips + parsedData.reimbursement);

        const grossPay =
        parsedData.salary_amt
        ? parsedData.salary_amt + parsedData.bonus + parsedData.tips + parsedData.vacationpay
        : regularPay + overtimePay + doubletimePay + parsedData.bonus + parsedData.tips + vacationtotal;


        console.log("Calculated Gross Pay:", grossPay);


        const annualGrossPay =
                data.frequency.toLowerCase() === "weekly"
                    ? grossPay * 52
                    : data.frequency.toLowerCase() === "biweekly"
                    ? grossPay * 26
                    : data.frequency.toLowerCase() === "semimonthly"
                    ? grossPay * 24
                    : grossPay * 12;

            const dependentReduction = parsedData.dependents * 2300;
            const standardDeduction = standardDeductions[filing_status] || 0;

            const adjustedAnnualIncome =
                annualGrossPay - dependentReduction - standardDeduction;

            console.log({
                grossPay,
                annualGrossPay,
                dependentReduction,
                standardDeduction,
                adjustedAnnualIncome,
            });

            // Calculate annual federal tax
            const federalTaxAnnual = await calculateFederalTax(adjustedAnnualIncome, filing_status);

            // Adjust federal tax to match the payroll period
            const federalTax =
                    data.frequency.toLowerCase() === "weekly"
                    ? federalTaxAnnual / 52
                    : data.frequency.toLowerCase() === "biweekly"
                    ? federalTaxAnnual / 26
                    : data.frequency.toLowerCase() === "semimonthly"
                    ? federalTaxAnnual / 24
                    : federalTaxAnnual / 12;

            console.log({ adjustedIncome: adjustedAnnualIncome, federalTax });

            const {stateTax, workTax} = await calculateStateTax(
                grossPay,
                data.frequency,
                e_state,
                b_state,
                parsedData.dependents,
                filing_status
            );

            const { businessTax, employeeTax } = await calculateCityTaxes(
                grossPay,
                b_city,
                e_city
            );

        // Calculate mandatory deductions
        const fedSS = grossPay * 0.062;
        const fedMed = grossPay * 0.0145;

        console.log("Mandatory Deductions: Fed SS:", fedSS, "Fed Med:", fedMed);





        // Calculate total deductions and net pay
        const deductions =
            federalTax +
            fedSS +
            fedMed +
            (stateTax || 0) +
            (workTax || 0) +
            businessTax +
            employeeTax +
            parsedData.cashadvance +
            parsedData.contrib_401k +
            parsedData.healthcare +
            parsedData.dental +
            parsedData.vision +
            parsedData.donation +
            parsedData.garnishment;

        const netPay = grossPay - deductions + parsedData.reimbursement;

        console.log("Deductions:", deductions);
        console.log("Calculated Net Pay:", netPay);

        // Validate required fields
        if (isNaN(grossPay) || isNaN(netPay)) {
            console.error("Invalid calculation results:", { grossPay, fedSS, fedMed, netPay });
            return res.status(400).json({ error: "Invalid calculation results." });
        }

        // Update the payroll record
        const updateQuery = `
            UPDATE payroll
            SET 
                state = ?,
                city = ?,
                business_state = ?,
                local_city1 = ?,
                local_city2 = ?,
                filing_status = ?,
                frequency = ?,
                salarypay = ?,
                hourly_rate = ?,
                ot_rate = ?,
                dt_rate = ?,
                regularhours = ?,
                overtimehours = ?,
                doubletimehours = ?,
                regularpay = ?,
                overtimepay = ?,
                doubletimepay = ?,
                vacation_total = ?,
                vacation_hours = ?,
                vacation_pay = ?,
                grosspay = ?,
                fed_tax = ?,
                state_tax = ?,
                work_state_tax = ?,
                local_citytax1 = ?,
                local_citytax2 = ?,
                fed_ss = ?,
                fed_med = ?,
                cashadvance = ?,
                contrib_401k = ?,
                healthcare = ?,
                dental = ?,
                vision = ?,
                donation = ?,
                garnishment = ?,
                bonus = ?,
                tips = ?,
                reimbursement = ?,
                net_pay = ?
            WHERE 
                user_id = ? AND 
                business_id = ? AND 
                id = ?
        `;
        const updateValues = [
            e_state,
            e_city,
            b_state,
            e_city,
            b_city,
            filing_status,
            data.frequency,
            parsedData.salary_amt,
            parsedData.hourly_rate,
            otRate,
            dtRate,
            parsedData.regularhours,
            parsedData.overtimehours,
            parsedData.doubletimehours,
            regularPay,
            overtimePay,
            doubletimePay,
            vacationtotal,
            parsedData.vacationhours,
            parsedData.vacationpay,
            grossPay,
            federalTax,
            stateTax,
            workTax,
            employeeTax,
            businessTax,
            fedSS,
            fedMed,
            parsedData.cashadvance,
            parsedData.contrib_401k,
            parsedData.healthcare,
            parsedData.dental,
            parsedData.vision,
            parsedData.donation,
            parsedData.garnishment,
            parsedData.bonus,
            parsedData.tips,
            parsedData.reimbursement,
            netPay,
            userId,
            businessId,
            id,
        ];

        console.log("Update Query Values:", updateValues);

        await new Promise((resolve, reject) => {
            db.query(updateQuery, updateValues, (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        console.log("Payroll record updated successfully.");
        res.status(200).json({ message: "Payroll record updated successfully." });
    } catch (error) {
        console.error("Error updating payroll record:", error);
        res.status(500).json({ error: "Failed to update payroll record." });
    }
});




app.get("/employees/:businessId/:employeeId", authenticateToken, (req, res) => {
    const { businessId, employeeId } = req.params;
    const userId = req.user?.id;

    if (!businessId || !employeeId || !userId) {
        return res.status(400).json({ error: "Invalid parameters." });
    }

    const query = `
        SELECT 
            id, 
            hourly_amt, 
            salary_amt, 
            filing_status, 
            dependents, 
            additional_fed_tax, 
            additional_state_tax, 
            e_state, 
            e_city, 
            contrib_401k, 
            healthcare, 
            dental, 
            vision, 
            donation, 
            garnishment
        FROM employees
        WHERE id = ? AND business_id = ? AND user_id = ?
    `;

    db.query(query, [employeeId, businessId, userId], (err, results) => {
        if (err) {
            console.error("Error fetching employee data:", err);
            return res.status(500).json({ error: "Failed to fetch employee data." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "No employee record found." });
        }

        res.json(results[0]);
    });
});




app.get("/user/profile", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extracted from authenticateToken middleware

    const query = `
        SELECT first_name, last_name
        FROM auth_app.users
        WHERE id = ? AND is_disabled = FALSE
    `;

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Error fetching user profile:", err);
            return res.status(500).json({ error: "Failed to fetch user profile." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "User not found or is disabled." });
        }

        const user = results[0];
        res.json({
            first_name: user.first_name,
            last_name: user.last_name,
        });
    });
});



app.put("/business/:businessId/set-bank-data", authenticateToken, (req, res) => {
    const { businessId } = req.params; // Extract business ID from URL
    const { bankName, routingNo, accountNo, checkNo } = req.body; // Data from the frontend
    const userId = req.user.id; // Extract user ID from the token


    console.log("Updating pay period for business:", businessId);
    console.log("Payload received:", { bankName, routingNo, accountNo, checkNo });

    const query = `
        UPDATE businesses 
        SET bank_name = ?, 
            routing_no = ?, 
            account_no = ?, 
            check_no = ? 
        WHERE owner_id = ? AND id = ?
    `;

    db.query(
        query,
        [bankName, routingNo, accountNo, checkNo, userId, businessId],
        (err,results) => {
            if (err) {
                console.error("Error updating business:", err);
                res.status(500).send("Failed to update bank info.");
                console.log("first error");
                return;
            }

            if (results.affectedRows === 0) {
                res.status(404).send("Business not found or unauthorized.");
                console.log("second motherfucker");
                return; // Stop further execution after sending a response
            }
            
            res.send("Bank info updated successfully.");
            console.log(results);
        }
        
    );
});



app.put("/business/:businessId/change-bank-data", authenticateToken, (req, res) => {
    const { businessId } = req.params; // Extract business ID from URL
    const { bankName, routingNo, accountNo, checkNo } = req.body; // Data from the frontend
    const userId = req.user.id; // Extract user ID from the token


    console.log("Updating pay period for business:", businessId);
    console.log("Payload received:", { bankName, routingNo, accountNo, checkNo });

    const query = `
        UPDATE businesses 
        SET bank_name = ?, 
            routing_no = ?, 
            account_no = ?, 
            check_no = ?,
            bankhaschanged = ? 
        WHERE owner_id = ? AND id = ?
    `;

    db.query(
        query,
        [bankName, routingNo, accountNo, checkNo, true, userId, businessId],
        (err,results) => {
            if (err) {
                console.error("Error updating business:", err);
                res.status(500).send("Failed to update bank info.");
                console.log("first error");
                return;
            }

            if (results.affectedRows === 0) {
                res.status(404).send("Business not found or unauthorized.");
                console.log("second motherfucker");
                return; // Stop further execution after sending a response
            }
            
            res.send("Bank info updated successfully.");
            console.log(results);
        }
        
    );
});


app.get("/business/:businessId/check-bank-data", authenticateToken, (req, res) => {
    const { businessId } = req.params; // Extract business ID from URL
    const userId = req.user.id; // Extract user ID from the token
    console.log(businessId,userId);

    console.log("Checking bank info for business:", businessId, "and owner:", userId);

    const query = `
        SELECT bank_name, routing_no, account_no, check_no 
        FROM businesses 
        WHERE id = ? AND owner_id = ?
    `;

    db.query(query, [businessId, userId], (err, results) => {
        if (err) {
            console.error("Error checking bank info:", err);
            res.status(500).send("Failed to check bank information.");
            return;
        }

        if (results.length === 0) {
            res.status(404).send("No business found or unauthorized.");
            return;
        }

        const bankInfo = results[0];

        // Check if any bank details are null or empty
        const hasBankData = bankInfo.bank_name && bankInfo.routing_no && bankInfo.account_no && bankInfo.check_no;

        if (hasBankData) {
            res.json({ exists: true, message: "Bank information exists.", bankInfo });
        } else {
            res.json({ exists: false, message: "Bank information is incomplete or missing." });
        }
    });
});







app.post("/payroll/print", authenticateToken, async (req, res) => {
    const { ids } = req.body;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: "Invalid or missing IDs." });
    }

    const payrollPlaceholders = ids.map(() => "?").join(", ");
    const payrollQuery = `
        SELECT business_id, employee_id, pay_date, name, hourly_rate, salarypay, ot_rate, dt_rate, 
               additional_fed_tax, additional_state_tax, regularhours, overtimehours, doubletimehours, contrib_401k, 
               healthcare, dental, vision, donation, garnishment, cashadvance, bonus, tips, reimbursement, regularpay, 
               overtimepay, doubletimepay, grosspay, fed_ss, fed_med, fed_tax, state_tax, county_tax, local_city1, 
               local_citytax1, local_city2, local_citytax2, business_state, work_state_tax, net_pay, e_st_add, city, state, e_suite, e_zip, start_date, end_date, vacation_hours, vacation_total, vacation_pay  
        FROM payroll
        WHERE id IN (${payrollPlaceholders}) AND user_id = ?
    `;

    const businessQuery = `
        SELECT name, b_stadd, b_suite, b_state, b_city, b_zip, bank_name, routing_no, account_no
        FROM businesses
        WHERE id = ?
    `;

    const ytdQuery = `
        SELECT 
            SUM(additional_fed_tax) AS additional_fed_tax,
            SUM(additional_state_tax) AS additional_state_tax,
            SUM(contrib_401k) AS contrib_401k,
            SUM(healthcare) AS healthcare,
            SUM(dental) AS dental,
            SUM(vision) AS vision,
            SUM(donation) AS donation,
            SUM(garnishment) AS garnishment,
            SUM(cashadvance) AS cashadvance,
            SUM(bonus) AS bonus,
            SUM(tips) AS tips,
            SUM(reimbursement) AS reimbursement,
            SUM(salarypay) AS salarypay,
            SUM(regularpay) AS regularpay,
            SUM(overtimepay) AS overtimepay,
            SUM(doubletimepay) AS doubletimepay,
            SUM(grosspay) AS grosspay,
            SUM(fed_ss) AS fed_ss,
            SUM(fed_med) AS fed_med,
            SUM(fed_tax) AS fed_tax,
            SUM(state_tax) AS state_tax,
            SUM(county_tax) AS county_tax,
            SUM(local_citytax1) AS local_citytax1,
            SUM(local_citytax2) AS local_citytax2,
            SUM(net_pay) AS net_pay,
            SUM(work_state_tax) AS work_state_tax,
            SUM(vacation_total) AS vacation_total,
            SUM(vacation_pay) AS vacation_pay
        FROM payroll
        WHERE user_id = ? AND business_id = ? AND employee_id = ? AND pay_date >= ? AND pay_date <= ?
    `;

    const fieldLabels = {
        salarypay: "Salary Pay",
        additional_fed_tax: "Additional FIT",
        additional_state_tax: "Additional SIT",
        regularpay: "Regular Pay",
        overtimepay: "Overtime Pay",
        doubletimepay: "Double Time Pay",
        grosspay: "Gross Pay",
        net_pay: "Net Pay",
        contrib_401k: "401K Contribution",
        healthcare: "Healthcare",
        dental: "Dental",
        vision: "Vision",
        donation: "Donation",
        garnishment: "Garnishment",
        cashadvance: "Cash Advance",
        bonus: "Bonus",
        tips: "Tips",
        reimbursement: "Reimbursement",
        fed_ss: "Social Security Tax",
        fed_med: "Medicare Tax",
        fed_tax: "Federal Tax",
        state_tax: "State Tax",
        county_tax: "County Tax",
        local_citytax1: "Local City Tax 1",
        local_citytax2: "Local City Tax 2",
        work_state_tax: "Work State Tax",
        vacation_hours: "Vacation Hours",
        vacation_total: "Vacation Amount",
        vacation_pay: "Vacation Pay",
    };

    

    const userId = req.user.id;

    db.query(payrollQuery, [...ids, userId], async (payrollErr, payrollResults) => {
        if (payrollErr) {
            console.error("Error fetching payroll data:", payrollErr);
            return res.status(500).json({ error: "Failed to fetch payroll data." });
        }

        if (!Array.isArray(payrollResults) || payrollResults.length === 0) {
            return res.status(404).json({ error: "No payroll records found for the selected IDs." });
        }

        const { business_id: businessId, pay_date: payDate } = payrollResults[0];
        console.log("Raw payrollResults:", payrollResults);
        console.log(businessId); // Output: 123
        console.log(payDate);    // Output: "2024-12-15"

        const yearStartDate = new Date(new Date(payDate).getFullYear(), 0, 1).toISOString().split("T")[0];
        console.log(yearStartDate); // Output: "2024-01-01"





        db.query(businessQuery, [businessId], async (businessErr, businessResults) => {
            if (businessErr) {
                console.error("Error fetching business data:", businessErr);
                return res.status(500).json({ error: "Failed to fetch business data." });
            }

            if (!Array.isArray(businessResults) || businessResults.length === 0) {
                return res.status(404).json({ error: "Business not found." });
            }

            const business = businessResults[0];

            try {
                const pdfDoc = await PDFDocument.create();
                const timesRomanFont = await pdfDoc.embedFont(StandardFonts.Helvetica);
                const timesBoldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
                const timesItalic = await pdfDoc.embedFont(StandardFonts.HelveticaBoldOblique)
                const fontSize = 8.5;

            

                const fieldGroups = [
                    {
                        name: "Wages",
                        fields: ["salarypay","regularpay", "overtimepay", "doubletimepay", "vacation_pay", "vacation_total"],
                        position: { x: 165, y: 275 },
                        xOffsets: { label: 0, current: 150, ytd: 200 },
                        width: 255,
                        height: 77,
                        position1: { x: 165, y: 535 },
                    },
                    {
                        name: "Deductions",
                        fields: ["contrib_401k", "healthcare", "dental", "vision", "donation", "garnishment", "cashadvance"],
                        position: { x: 395, y: 198 },
                        xOffsets: { label: 0, current: 110, ytd: 150 },
                        width: 205,
                        height: 110,
                        position1: { x: 395, y: 458 },
                    },
                    {
                        name: "Other Income",
                        fields: ["bonus", "tips", "reimbursement"],
                        position: { x: 420, y: 275 },
                        xOffsets: { label: 0, current: 85, ytd: 130 },
                        width: 180,
                        height: 77,
                        position1: { x: 420, y: 535 },
                    },
                    {
                        name: "Taxes",
                        fields: ["fed_ss", "fed_med", "fed_tax", "state_tax", "additional_fed_tax", "additional_state_tax", "county_tax", "local_citytax1", "local_citytax2", "work_state_tax"],
                        position: { x: 165, y: 198 },
                        xOffsets: { label: 0, current: 120, ytd: 180 },
                        width: 230,
                        height: 153,
                        position1: { x: 165, y: 458 },
                    },
                    {
                        name: "Pay Summary", // New Group
                        fields: ["grosspay", "net_pay"],
                        position: { x: 395, y: 88 },
                        xOffsets: { label: 0, current: 100, ytd: 150 },
                        width: 205,
                        height: 43,
                        position1: { x: 395, y: 348 },
                        excludeFromTotals: true, // Add this flag
                    },
                ];

                for (const record of payrollResults) {
                    const { employee_id: employeeId, pay_date: endDate } = record;

                    const ytdResults = await new Promise((resolve, reject) => {
                        db.query(ytdQuery, [userId, businessId, employeeId, yearStartDate, endDate], (ytdErr, ytdData) => {
                            if (ytdErr) return reject(ytdErr);
                            resolve(ytdData[0]);
                        });
                    });

                    const page = pdfDoc.addPage([600, 800]);


                    const formatValue = (value) => {
                        if (value === null || value === undefined || value === "0.00" || value === "0") return ""; // Treat these as blank
                        return value; // Keep other values as-is
                    };
                    



                        // const rateTable = {
                        //     position: { x: 245, y: 263 },
                        //     position1: { x: 245, y: 523 },
                        //     width: 50,
                        //     height: 100,
                        //     fields: [
                        //         { value: formatValue(record.hourly_rate) || "" },
                        //         ...(record.overtimehours !== null && record.overtimehours !== "0.00" ? [{ value: formatValue(record.ot_rate) || "" }] : []),
                        //         ...(record.doubletimehours !== null && record.doubletimehours !== "0.00" ? [{ value: formatValue(record.dt_rate) || "" }] : []),
                        //         ...(record.vacation_hours !== null && record.vacation_hours !== "0.00" ? [{ value: formatValue(record.hourly_rate) || "" }] : []),
                        //     ],
                        // };


                        const rateTable = {
                            position: { x: 245, y: 263 },
                            position1: { x: 245, y: 523 },
                            width: 50,
                            height: 100,
                            fields: [
                                // Hourly rate
                                record.regularhours !== null && record.regularhours !== "0.00"
                                    ? { value: formatValue(record.hourly_rate) || "" }
                                    : { value: "" },
                        
                                // Overtime rate
                                record.overtimehours !== null && record.overtimehours !== "0.00"
                                    ? { value: formatValue(record.ot_rate) || "" }
                                    : { value: "" },
                        
                                // Double-time rate
                                record.doubletimehours !== null && record.doubletimehours !== "0.00"
                                    ? { value: formatValue(record.dt_rate) || "" }
                                    : { value: "" },
                        
                                // Vacation rate
                                record.vacation_hours !== null && record.vacation_hours !== "0.00"
                                    ? { value: formatValue(record.hourly_rate) || "" }
                                    : { value: "" },
                            ],
                        };
                        


                        const hoursTable = {
                            position: { x: 280, y: 263 },
                            position1: { x: 280, y: 523 },
                            width: 50,
                            height: 100,
                            fields: [
                                { value: formatValue(record.regularhours) },
                                { value: formatValue(record.overtimehours)},
                                { value: formatValue(record.doubletimehours)},
                                { value: formatValue(record.vacation_hours)},

                            ],
                        };
                        


                        

                        
                        
                        // Calculate total hours
                        //const totalHours = hoursTable.fields.reduce((sum, field) => sum + (field.value || ""), 0);
                        const totalHours = hoursTable.fields.reduce(
                            (sum, field) => sum + parseFloat(field.value || 0),
                            0
                        );

                        function numberToWords(amount) {
                            const units = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"];
                            const teens = ["Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"];
                            const tens = ["", "Ten", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"];
                            const thousands = ["", "Thousand", "Million", "Billion", "Trillion"];
                        
                            function convertToWords(num) {
                                if (num === 0) return "Zero";
                                if (num < 10) return units[num];
                                if (num < 20) return teens[num - 11];
                                if (num < 100) return tens[Math.floor(num / 10)] + (num % 10 !== 0 ? " " + units[num % 10] : "");
                                if (num < 1000) return units[Math.floor(num / 100)] + " Hundred" + (num % 100 !== 0 ? " " + convertToWords(num % 100) : "");
                        
                                for (let i = thousands.length - 1; i >= 0; i--) {
                                    const divisor = Math.pow(1000, i);
                                    if (num >= divisor) {
                                        return (
                                            convertToWords(Math.floor(num / divisor)) +
                                            " " +
                                            thousands[i] +
                                            (num % divisor !== 0 ? " " + convertToWords(num % divisor) : "")
                                        );
                                    }
                                }
                            }
                        
                            const integerPart = Math.floor(amount);
                            const decimalPart = Math.round((amount - integerPart) * 100);
                        
                            let words = convertToWords(integerPart) + " Dollars";
                            if (decimalPart > 0) {
                                words += " and " + decimalPart + "/100";
                            }
                            return words;
                        }
                        
                        
                        

                        const amount = record.net_pay;
                        console.log(numberToWords(amount));
                        // Output: "One Thousand Two Hundred Thirty-Four Dollars and 56/100"
                            

                        
                    const employeeTable = {
                        position: { x: 5, y: 230 },
                        position1: { x: 5, y: 490 },
                        width: 130,
                        height: 50,
                        fields: [
                            { value: record.name || "" , font: timesBoldFont }, // Business Name
                            { value: record.e_st_add || "" , font: timesRomanFont }, // Street
                            { value: record.e_suite || "" , font: timesRomanFont }, // Suite (may be null)
                            { value: `${record.city || ""}, ${record.state || ""}, ${record.e_zip || ""}`, font: timesRomanFont }, // City, State, Zip
                        ],
                    }

                    console.log("employeeTable.fields:", employeeTable.fields);


                    const employeefilteredFields = (employeeTable.fields || []).filter(({ value }) =>
                        value !== null && value !== undefined && value.trim() !== ""
                    );
                    
                    console.log("Filtered fields:", employeefilteredFields);


                    const businessTable = {
                        position: { x: 5, y: 275 },
                        position1: { x: 5, y: 535 },
                        width: 155,
                        height: 230,
                        fields: [
                            { value: business.name.toUpperCase() || "" , font: timesBoldFont }, // Business Name
                            { value: business.b_stadd || "" , font: timesRomanFont}, // Street
                            { value: business.b_suite || "" , font: timesRomanFont }, // Suite (may be null)
                            { value: `${business.b_city || ""}, ${business.b_state || ""}, ${business.b_zip || ""}`, font: timesRomanFont }, // City, State, Zi
                        ],
                    }

                    console.log("businessTable.fields:", businessTable.fields);


                    const filteredFields = (businessTable.fields || []).filter(({ value }) =>
                        value !== null && value !== undefined && value.trim() !== ""
                    );
                    
                    console.log("Filtered fields:", filteredFields);

                    // Filter out rows with empty or null values
                    

                  
                    // Render Business Info
                    
                    // Render Groups
                    fieldGroups.forEach(({ name, fields, position, position1, xOffsets, width, height, excludeFromTotals }) => {

                        // Render group at the primary position
                            renderGroup(name, fields, position, xOffsets, width, height, excludeFromTotals);

                            // Render group at the secondary position
                            renderGroup(name, fields, position1, xOffsets, width, height, excludeFromTotals);
                        });

                        // Helper function to render a group at a given position
                        function renderGroup(name, fields, position, xOffsets, width, height, excludeFromTotals) {

                        let { x, y } = position;

                        const { label, current, ytd } = xOffsets;


                        let groupCurrentTotal = 0;
                        let groupYTDTotal = 0;

                        // Draw group border
                        page.drawRectangle({
                            x: x - 5,
                            y: y - height,
                            width: width ,
                            height: height,
                            borderColor: rgb(0, 0, 0),
                            borderWidth: 1,
                        });

                        // Draw header background
                        page.drawRectangle({
                            x: x - 5,
                            y: y - 12,
                            width: width ,
                            height: 12,
                            borderColor: rgb(0, 0, 0),
                            borderWidth: 1, // Black background
                        });

                        console.log(label,current,ytd);

                        // Draw header text
                        page.drawText(name, { x: x + label, y: y - 9, size: fontSize, font: timesItalic, color: rgb(0, 0, 0) });

                        // Draw "Current" and "YTD" headers
                        page.drawText("Amount", { x: x + current , y: y - 9, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont});
                        page.drawText("YTD", { x: x + ytd + 4, y: y - 9, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });

                        let rowY = y - 22; // Start rendering rows below the header






                        fields.forEach((field) => {
                            const fieldLabel = fieldLabels[field] || field.replace(/_/g, " ").toUpperCase();
                            const currentValue = record[field];
                            const ytdValue = ytdResults[field];

                            
                        
                            // Check if both currentValue and ytdValue are null, 0, or 0.00
                            if (
                                (currentValue === null || currentValue === 0 || currentValue === "0.00") &&
                                (ytdValue === null || ytdValue === 0 || ytdValue === "0.00")
                            ) {
                                // Skip rendering this field
                                return;
                            }

                            // Render a grey rectangle for Net Pay field
                            if (field === "net_pay") {
                                const rectangleX = x + label - 5; // Adjust based on your layout
                                const rectangleY = rowY +11;     // Position slightly above Net Pay
                                const rectangleWidth = width;   // Match the group width
                                const rectangleHeight = 17;     // Height of the rectangle

                                page.drawRectangle({
                                    x: rectangleX,
                                    y: rectangleY - rectangleHeight,
                                    width: rectangleWidth,
                                    height: rectangleHeight,
                                    color: rgb(0.9, 0.9, 0.9), // Light grey background
                                    borderColor: rgb(0, 0, 0),
                                    borderWidth: 1,
                                });
                            }

                            // Render currentValue as blank if it is 0 or "0.00"
                            const displayCurrentValue = currentValue === 0 || currentValue === "0.00" ? "" : currentValue;

                            // Use bold font for Net Pay
                            const fontToUse = field === "net_pay" ? timesBoldFont : timesRomanFont;
                            // Use bold font for the Net Pay label
                            const labelFont = field === "net_pay" ? timesBoldFont : timesRomanFont;


                                                // Add to totals if not excluded
                            if (!excludeFromTotals) {
                                groupCurrentTotal += parseFloat(currentValue || 0);
                                groupYTDTotal += parseFloat(ytdValue || 0);
                            }

                        
                            // Render the field if the condition is not met
                            page.drawText(`${fieldLabel}:`, { x: x + label, y:rowY, size: fontSize, font: labelFont });
                            page.drawText(`${displayCurrentValue || ""}`, { x: x + current, y:rowY, size: fontSize, font: fontToUse });
                            page.drawText(`${ytdValue || ""}`, { x: x + ytd, y:rowY, size: fontSize, font: timesRomanFont });
                            //rowY -= 10; // Move to the next row
                            // Apply custom spacing for "Pay Summary" group
                            if (name === "Pay Summary") {
                                rowY -= 15; // Custom spacing for Pay Summary
                            } else {
                                rowY -= 10; // Default spacing for other groups
                            }
                        });


                        if (excludeFromTotals) return;                        
                        // Render totals at a static position at the bottom of the group
                        const totalsY = y - height; // Adjust for padding at the bottom

                        // Draw a rectangle for the totals section
                        page.drawRectangle({
                            x: x + label - 5,
                            y: totalsY  , // Adjust to cover the totals section
                            width: width,
                            height: 12, // Adjust the height of the totals rectangle
                            color: rgb(0.9, 0.9, 0.9), // Light gray background
                            borderColor: rgb(0, 0, 0),
                            borderWidth: 1,
                        });

                        const displayGroupCurrentTotal = groupCurrentTotal === 0 ? "" : groupCurrentTotal.toFixed(2);
                        const displayGroupYTDTotal = groupYTDTotal === 0 ? "" : groupYTDTotal.toFixed(2);
                         

                        page.drawText("Total", { x: x, y: totalsY +3, size: fontSize, font: timesBoldFont });
                        page.drawText(`${displayGroupCurrentTotal}`, { x: x + current - 1, y: totalsY+3, size: fontSize , font: timesBoldFont });
                        page.drawText(`${displayGroupYTDTotal}`, { x: x + ytd - 1, y: totalsY+3, size: fontSize , font: timesBoldFont });
                        


        


                        const displayHoursTotal = totalHours === 0 ? "" : totalHours.toFixed(2);

                        // Draw the business info table
                        page.drawText("Rate", { x: 246, y: 266, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        page.drawText("Hours", { x: 279, y: 266, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        page.drawText(`${displayHoursTotal || "" }`, { x: 280, y: 201, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        
                        // Draw the business info table
                        page.drawText("Rate", { x: 246, y: 526, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        page.drawText("Hours", { x: 279, y: 526, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        page.drawText(`${displayHoursTotal || "" }`, { x: 280, y: 461, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        
                        page.drawText(`${record.pay_date.toLocaleDateString()}`, { x: 500, y: 710, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        page.drawText(`${record.net_pay}`, { x: 470, y: 690, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        page.drawText(record.name, { x: 75, y: 700, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        page.drawText(`Payroll Period: ${record.start_date.toLocaleDateString()} ${record.end_date.toLocaleDateString()}`, { x: 25, y: 590, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });
                        page.drawText((numberToWords(amount)), { x: 70, y: 680, size: fontSize,color: rgb(0, 0, 0), font: timesRomanFont });  


                                                // Render Business Table
                        [businessTable.position, businessTable.position1].forEach((position) => {
                            const { x, y } = position;

                            // Draw the business info rectangle
                            page.drawRectangle({
                                x: x,
                                y: y - businessTable.height,
                                width: businessTable.width,
                                height: businessTable.height,
                                borderColor: rgb(0, 0, 0), // Black border
                                borderWidth: 1,
                            });

                            let businessTextY = y - 10;
                            filteredFields.forEach(({ value, font }) => {
                                page.drawText(`${value}`, {
                                    x: x + 2,
                                    y: businessTextY,
                                    size: fontSize,
                                    font: font,
                                    color: rgb(0, 0, 0),
                                });
                                businessTextY -= fontSize + 1; // Move down for the next row
                            });
                        });

                        // Render Employee Table
                        [employeeTable.position, employeeTable.position1].forEach((position) => {
                            const { x, y } = position;


                            let employeeTextY = y - 10;
                            employeefilteredFields.forEach(({ value, font }) => {
                                page.drawText(`${value}`, {
                                    x: x + 2,
                                    y: employeeTextY,
                                    size: fontSize,
                                    font: font,
                                    color: rgb(0, 0, 0),
                                });
                                employeeTextY -= fontSize + 1; // Move down for the next row
                            });
                        });



                        // let employeesTextY = employeeTable.position.y - 10;
                        // employeefilteredFields.forEach(({ value, font }) => {
                        //     page.drawText(`${value}`, { x: employeeTable.position.x + 2, y: employeesTextY, size: fontSize, font: font, color: rgb(0, 0, 0) });
                        //     employeesTextY -= fontSize+1; // Move down for the next row
                        // });

                        
                        
                        // Render Employee Table
                        [rateTable.position, rateTable.position1].forEach((position) => {
                            const { x, y } = position;


                            let rateTextY = y - 10;
                            rateTable.fields.forEach(({ value }) => {
                                page.drawText(`${value}`, {
                                    x: x ,
                                    y: rateTextY,
                                    size: fontSize,
                                    color: rgb(0, 0, 0),
                                });
                                rateTextY -= 10; // Move down for the next row
                            });
                        });

                        // Render Employee Table
                        [hoursTable.position, hoursTable.position1].forEach((position) => {
                            const { x, y } = position;


                            let hoursTextY = y - 10;
                            hoursTable.fields.forEach(({ value }) => {
                                page.drawText(`${value}`, {
                                    x: x ,
                                    y: hoursTextY,
                                    size: fontSize,
                                    color: rgb(0, 0, 0),
                                });
                                hoursTextY -= 10; // Move down for the next row
                            });
                        });


                        
                        

                        };


                        };

                const pdfBytes = await pdfDoc.save();

                res.setHeader("Content-Type", "application/pdf");
                res.setHeader("Content-Disposition", "attachment; filename=paystub.pdf");
                res.send(Buffer.from(pdfBytes));
            } catch (pdfErr) {
                console.error("Error generating PDF:", pdfErr);
                res.status(500).json({ error: "Failed to generate PDF." });
            }
        });
    });
});



app.get("/payroll/recent/full/:businessId", authenticateToken, (req, res) => {
    const businessId = parseInt(req.params.businessId, 10); // Parse businessId from the URL
    const userId = req.user.id; // Retrieve userId from the authenticated token

    // SQL query to fetch all columns from the most recent payroll record
    const query = `
        SELECT * 
        FROM payroll
        WHERE business_id = ? 
          AND user_id = ? 
          AND end_date = (
              SELECT MAX(end_date) 
              FROM payroll 
              WHERE business_id = ? AND user_id = ?
          )
          AND start_date = (
              SELECT MAX(start_date) 
              FROM payroll 
              WHERE business_id = ? AND user_id = ?
          )
          AND pay_date = (
              SELECT MAX(pay_date) 
              FROM payroll 
              WHERE business_id = ? AND user_id = ?
          );
    `;

    // Execute the query with prepared statements
    db.query(
        query, 
        [businessId, userId, businessId, userId, businessId, userId, businessId, userId], 
        (err, results) => {
            if (err) {
                console.error("Error fetching recent payroll data:", err);
                return res.status(500).json({ error: "Failed to fetch payroll data." });
            }

            // Handle case where no records are found
            if (results.length === 0) {
                return res.status(404).json({ message: "No payroll records found for the most recent pay period." });
            }

            // Respond with the retrieved records
            res.json(results);
        }
    );
});



app.post("/payroll/filter/:businessId", authenticateToken, (req, res) => {
    const businessId = parseInt(req.params.businessId, 10);
    const userId = req.user.id;
    const { startDate, endDate } = req.body;

    if (!startDate || !endDate) {
        return res.status(400).json({ error: "Start date and end date are required." });
    }

    const query = `
        SELECT 
            EMPLOYEE_ID, NAME, GROSSPAY, NET_PAY, FED_TAX, STATE_TAX, PAY_DATE
        FROM payroll
        WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?
        ORDER BY EMPLOYEE_ID, PAY_DATE;
    `;

    const sumQuery = `
        SELECT 
            SUM(GROSSPAY) AS totalGrossPay, 
            SUM(NET_PAY) AS totalNetPay, 
            SUM(FED_TAX) AS totalFedTax, 
            SUM(STATE_TAX) AS totalStateTax
        FROM payroll
        WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?;
    `;

    // Fetch filtered records
    db.query(query, [businessId, userId, startDate, endDate], (err, results) => {
        if (err) {
            console.error("Error fetching filtered payroll data:", err);
            return res.status(500).json({ error: "Failed to fetch payroll data." });
        }

        // Fetch sum
        db.query(sumQuery, [businessId, userId, startDate, endDate], (sumErr, sumResults) => {
            if (sumErr) {
                console.error("Error calculating sum of payroll data:", sumErr);
                return res.status(500).json({ error: "Failed to calculate payroll totals." });
            }

            const totals = sumResults[0];
            res.json({ totals, records: results });
        });
    });
});


// app.post("/payroll/pdf/:businessId", authenticateToken, (req, res) => {
//     const businessId = parseInt(req.params.businessId, 10);
//     const userId = req.user.id;
//     const { startDate, endDate } = req.body;

//     if (!startDate || !endDate) {
//         return res.status(400).json({ error: "Start date and end date are required." });
//     }

//     const query = `
//         SELECT 
//             EMPLOYEE_ID, NAME, GROSSPAY, NET_PAY, FED_TAX, STATE_TAX, PAY_DATE
//         FROM payroll
//         WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?
//         ORDER BY EMPLOYEE_ID, PAY_DATE;
//     `;

//     console.log("Executing query:", query);
//     console.log("With parameters:", [businessId, userId, startDate, endDate])

//     db.query(query, [businessId, userId, startDate, endDate], async (err, results) => {
//         if (err) {
//             console.error("Error fetching payroll data for PDF:", err);
//             return res.status(500).json({ error: "Failed to fetch payroll data for PDF." });
//         }

//         if (results.length === 0) {
//             return res.status(404).json({ error: "No payroll data found for the specified date range." });
//         }

//         try {
//             // Group payroll data by employee
//             const groupedData = results.reduce((acc, record) => {
//                 if (!acc[record.NAME]) {
//                     acc[record.NAME] = [];
//                 }
//                 acc[record.NAME].push(record);
//                 return acc;
//             }, {});

//             // Create the PDF document
//             const { PDFDocument, rgb } = require("pdf-lib");
//             const pdfDoc = await PDFDocument.create();
//             const page = pdfDoc.addPage([600, 800]); // Letter size
//             const fontSize = 8;

//             let y = 750; // Start position for writing

//             // Add Title
//             page.drawText(`Payroll Report for Business ID: ${businessId}`, {
//                 x: 50,
//                 y,
//                 size: fontSize + 4,
//                 color: rgb(0, 0, 0),
//             });
//             y -= 20;

//             // Add Date Range
//             page.drawText(`Date Range: ${startDate} - ${endDate}`, {
//                 x: 50,
//                 y,
//                 size: fontSize,
//                 color: rgb(0, 0, 0),
//             });
//             y -= 20;

//             // Add Employee Data
//             Object.entries(groupedData).forEach(([employeeName, records]) => {
//                 if (y < 50) {
//                     y = 750; // Reset y position for a new page
//                     pdfDoc.addPage(); // Add a new page
//                 }

                


//                 // Employee Name
//                 page.drawText(`Employee: ${employeeName}`, {
//                     x: 50,
//                     y,
//                     size: fontSize + 2,
//                     color: rgb(0.2, 0.4, 0.8),
//                 });
//                 y -= 20;

//                 // Employee Records
//                 records.forEach((record) => {
//                     if (y < 50) {
//                         y = 750;
//                         pdfDoc.addPage();
//                     }

//                     const payDate = new Date(record.PAY_DATE).toLocaleDateString();
            




//                     page.drawText(
//                         `Date: ${payDate}}, Gross Pay: $${record.GROSSPAY}, Net Pay: $${record.NET_PAY}, Federal Tax: $${record.FED_TAX}, State Tax: $${record.STATE_TAX}`,
//                         {
//                             x: 50,
//                             y,
//                             size: fontSize,
//                             color: rgb(0, 0, 0),
//                         }
//                     );
//                     y -= 20;
//                 });
//                 y -= 10; // Add some space after each employee's data
//             });

//             // Serialize the PDF document to bytes
//             const pdfBytes = await pdfDoc.save();

//             // Send the PDF as a response
//             res.setHeader("Content-Type", "application/pdf");
//             res.setHeader("Content-Disposition", `attachment; filename=payroll_${businessId}.pdf`);
//             res.send(Buffer.from(pdfBytes));
//         } catch (pdfErr) {
//             console.error("Error generating PDF:", pdfErr);
//             res.status(500).json({ error: "Failed to generate PDF." });
//         }
//     });
// });


// app.post("/payroll/pdf/:businessId", authenticateToken, async (req, res) => {
//     const businessId = parseInt(req.params.businessId, 10);
//     const userId = req.user.id;
//     const { startDate, endDate } = req.body;
  
//     if (!startDate || !endDate) {
//       return res.status(400).json({ error: "Start date and end date are required." });
//     }
  
//     const recordsQuery = `
//       SELECT 
//           EMPLOYEE_ID, NAME, GROSSPAY, NET_PAY, FED_TAX, STATE_TAX, PAY_DATE
//       FROM payroll
//       WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?
//       ORDER BY EMPLOYEE_ID, PAY_DATE;
//     `;
  
//     const sumQuery = `
//       SELECT 
//     COALESCE(SUM(GROSSPAY), 0) AS totalGrossPay, 
//     COALESCE(SUM(NET_PAY), 0) AS totalNetPay, 
//     COALESCE(SUM(FED_TAX), 0) AS totalFedTax, 
//     COALESCE(SUM(STATE_TAX), 0) AS totalStateTax
//     FROM payroll
//     WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?;

//     `;
  
//     db.query(recordsQuery, [businessId, userId, startDate, endDate], async (err, records) => {
//       if (err) {
//         console.error("Error fetching payroll data:", err);
//         return res.status(500).json({ error: "Failed to fetch payroll data." });
//       }
  
//       if (records.length === 0) {
//         return res.status(404).json({ error: "No payroll data found for the specified date range." });
//       }
  
//       db.query(sumQuery, [businessId, userId, startDate, endDate], async (sumErr, totals) => {
//         if (sumErr) {
//           console.error("Error calculating totals:", sumErr);
//           return res.status(500).json({ error: "Failed to calculate payroll totals." });
//         }
  
//         const overallTotals = totals[0];
  
//         // Group records by employee and calculate per-employee totals
//         const groupedData = records.reduce((acc, record) => {
//           if (!acc[record.NAME]) {
//             acc[record.NAME] = { records: [], totals: { grossPay: 0, netPay: 0, federalTax: 0, stateTax: 0 } };
//           }
//           acc[record.NAME].records.push(record);
//           acc[record.NAME].totals.grossPay += parseFloat(record.GROSSPAY || 0);
//           acc[record.NAME].totals.netPay += parseFloat(record.NET_PAY || 0);
//           acc[record.NAME].totals.federalTax += parseFloat(record.FED_TAX || 0);
//           acc[record.NAME].totals.stateTax += parseFloat(record.STATE_TAX || 0);
//           return acc;
//         }, {});
  
//         try {
//           const { PDFDocument, rgb } = require("pdf-lib");
//           const pdfDoc = await PDFDocument.create();
//           const page = pdfDoc.addPage([600, 800]); // Letter size
//           const fontSize = 12;
  
//           let y = 750;
  
//           // Add Title
//           page.drawText(`Payroll Report for Business ID: ${businessId}`, { x: 50, y, size: fontSize + 4, color: rgb(0, 0, 0) });
//           y -= 20;
  
//           // Add Date Range
//           page.drawText(`Date Range: ${startDate} - ${endDate}`, { x: 50, y, size: fontSize, color: rgb(0, 0, 0) });
//           y -= 20;
  
//           // Add Overall Totals
//           page.drawText(`Overall Totals:`, { x: 50, y, size: fontSize + 2, color: rgb(0.2, 0.4, 0.8) });
//           y -= 20;
//           page.drawText(
//             `Gross Pay: $${overallTotals.totalGrossPay}, Net Pay: $${overallTotals.totalNetPay}, Federal Tax: $${overallTotals.totalFedTax}, State Tax: $${overallTotals.totalStateTax}`,
//             { x: 50, y, size: fontSize, color: rgb(0, 0, 0) }
//           );
//           y -= 30;
  
//           // Add Employee Data
//           Object.entries(groupedData).forEach(([employeeName, { records, totals }]) => {
//             if (y < 50) {
//               y = 750;
//               pdfDoc.addPage();
//             }
  
//             // Employee Name
//             page.drawText(`Employee: ${employeeName}`, { x: 50, y, size: fontSize + 2, color: rgb(0.2, 0.4, 0.8) });
//             y -= 20;
  
//             // Employee Totals
//             page.drawText(
//               `Totals - Gross Pay: $${totals.grossPay}, Net Pay: $${totals.netPay}, Federal Tax: $${totals.federalTax}, State Tax: $${totals.stateTax}`,
//               { x: 50, y, size: fontSize, color: rgb(0, 0, 0) }
//             );
//             y -= 20;
  
//             // Employee Records
//             records.forEach((record) => {
//               if (y < 50) {
//                 y = 750;
//                 pdfDoc.addPage();
//               }
//               page.drawText(
//                 `Date: ${new Date(record.PAY_DATE).toLocaleDateString()}, Gross Pay: $${record.GROSSPAY}, Net Pay: $${record.NET_PAY}, Federal Tax: $${record.FED_TAX}, State Tax: $${record.STATE_TAX}`,
//                 { x: 50, y, size: fontSize, color: rgb(0, 0, 0) }
//               );
//               y -= 20;
//             });
//             y -= 10;
//           });
  
//           // Serialize and send the PDF
//           const pdfBytes = await pdfDoc.save();
//           res.setHeader("Content-Type", "application/pdf");
//           res.setHeader("Content-Disposition", `attachment; filename=payroll_${businessId}.pdf`);
//           res.send(Buffer.from(pdfBytes));
//         } catch (pdfErr) {
//           console.error("Error generating PDF:", pdfErr);
//           res.status(500).json({ error: "Failed to generate PDF." });
//         }
//       });
//     });
//   });
  


// app.post("/payroll/pdf/:businessId", authenticateToken, async (req, res) => {
//     const businessId = parseInt(req.params.businessId, 10);
//     const userId = req.user.id;
//     const { startDate, endDate } = req.body;

//     if (!startDate || !endDate) {
//         return res.status(400).json({ error: "Start date and end date are required." });
//     }

//     const recordsQuery = `
//       SELECT 
//           EMPLOYEE_ID, NAME, GROSSPAY, NET_PAY, FED_TAX, STATE_TAX, PAY_DATE
//       FROM payroll
//       WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?
//       ORDER BY EMPLOYEE_ID, PAY_DATE;
//     `;

//     const sumQuery = `
//       SELECT 
//           COALESCE(SUM(GROSSPAY), 0) AS totalGrossPay, 
//           COALESCE(SUM(NET_PAY), 0) AS totalNetPay, 
//           COALESCE(SUM(FED_TAX), 0) AS totalFedTax, 
//           COALESCE(SUM(STATE_TAX), 0) AS totalStateTax
//       FROM payroll
//       WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?;
//     `;

//     db.query(recordsQuery, [businessId, userId, startDate, endDate], async (err, records) => {
//         if (err) {
//             console.error("Error fetching payroll data:", err);
//             return res.status(500).json({ error: "Failed to fetch payroll data." });
//         }

//         if (records.length === 0) {
//             return res.status(404).json({ error: "No payroll data found for the specified date range." });
//         }

//         db.query(sumQuery, [businessId, userId, startDate, endDate], async (sumErr, totals) => {
//             if (sumErr) {
//                 console.error("Error calculating totals:", sumErr);
//                 return res.status(500).json({ error: "Failed to calculate payroll totals." });
//             }

//             const overallTotals = totals[0];

//             // Group records by employee and calculate per-employee totals
//             const groupedData = records.reduce((acc, record) => {
//                 if (!acc[record.NAME]) {
//                     acc[record.NAME] = { records: [], totals: { grossPay: 0, netPay: 0, federalTax: 0, stateTax: 0 } };
//                 }
//                 acc[record.NAME].records.push(record);
//                 acc[record.NAME].totals.grossPay += parseFloat(record.GROSSPAY || 0);
//                 acc[record.NAME].totals.netPay += parseFloat(record.NET_PAY || 0);
//                 acc[record.NAME].totals.federalTax += parseFloat(record.FED_TAX || 0);
//                 acc[record.NAME].totals.stateTax += parseFloat(record.STATE_TAX || 0);
//                 return acc;
//             }, {});

//             try {
//                 const { PDFDocument, rgb } = require("pdf-lib");
//                 const fs = require("fs");
//                 const pdfDoc = await PDFDocument.create();
//                 const logoBytes = fs.readFileSync("payweek.png"); // Replace with your logo path
//                 const logoImage = await pdfDoc.embedPng(logoBytes);
//                 const logoDimensions = logoImage.scale(0.07); // Adjust scale as needed

//                 let page = pdfDoc.addPage([600, 800]); // Letter size
//                 let y = 750;
//                 const fontSize = 10;

//                 // Helper to add a new page
//                 const addNewPage = () => {
//                     page = pdfDoc.addPage([600, 800]);
//                     y = 750;
//                     page.drawImage(logoImage, {
//                         x: 50,
//                         y: page.getHeight() - logoDimensions.height - 20,
//                         width: logoDimensions.width,
//                         height: logoDimensions.height,
//                     });
//                 };

//                 // Draw the logo on the first page
//                 page.drawImage(logoImage, {
//                     x: 450,
//                     y: page.getHeight() - logoDimensions.height - 20,
//                     width: logoDimensions.width,
//                     height: logoDimensions.height,
//                 });

//                 // Add Title
//                 page.drawText(`Payroll Report for Business ID: ${businessId}`, { x: 50, y, size: fontSize + 4, color: rgb(0, 0, 0) });
//                 y -= 20;

//                 // Add Date Range
//                 page.drawText(`Date Range: ${startDate} - ${endDate}`, { x: 50, y, size: fontSize, color: rgb(0, 0, 0) });
//                 y -= 20;

//                 // Add Overall Totals
//                 page.drawText(`Overall Totals:`, { x: 50, y, size: fontSize + 2, color: rgb(0.2, 0.4, 0.8) });
//                 y -= 20;
//                 page.drawText(
//                     `Gross Pay: $${overallTotals.totalGrossPay}, Net Pay: $${overallTotals.totalNetPay}, Federal Tax: $${overallTotals.totalFedTax}, State Tax: $${overallTotals.totalStateTax}`,
//                     { x: 50, y, size: fontSize, color: rgb(0, 0, 0) }
//                 );
//                 y -= 30;

//                 // Add Employee Data
//                 Object.entries(groupedData).forEach(([employeeName, { records, totals }]) => {
//                     if (y < 50) addNewPage();

//                     // Employee Name
//                     page.drawText(`Employee: ${employeeName}`, { x: 50, y, size: fontSize + 2, color: rgb(0.2, 0.4, 0.8) });
//                     y -= 20;

//                     // Employee Totals
//                     page.drawText(
//                         `Totals - Gross Pay: $${totals.grossPay}, Net Pay: $${totals.netPay}, Federal Tax: $${totals.federalTax}, State Tax: $${totals.stateTax}`,
//                         { x: 50, y, size: fontSize, color: rgb(0, 0, 0) }
//                     );
//                     y -= 20;

//                     // Employee Records
//                     records.forEach((record) => {
//                         if (y < 50) addNewPage();

//                         page.drawText(
//                             `Date: ${new Date(record.PAY_DATE).toLocaleDateString()}, Gross Pay: $${record.GROSSPAY}, Net Pay: $${record.NET_PAY}, Federal Tax: $${record.FED_TAX}, State Tax: $${record.STATE_TAX}`,
//                             { x: 50, y, size: fontSize, color: rgb(0, 0, 0) }
//                         );
//                         y -= 20;
//                     });
//                     y -= 10;
//                 });

//                 // Serialize and send the PDF
//                 const pdfBytes = await pdfDoc.save();
//                 res.setHeader("Content-Type", "application/pdf");
//                 res.setHeader("Content-Disposition", `attachment; filename=payroll_${businessId}.pdf`);
//                 res.send(Buffer.from(pdfBytes));
//             } catch (pdfErr) {
//                 console.error("Error generating PDF:", pdfErr);
//                 res.status(500).json({ error: "Failed to generate PDF." });
//             }
//         });
//     });
// });

// app.post("/payroll/pdf/:businessId", authenticateToken, async (req, res) => {
//     const businessId = parseInt(req.params.businessId, 10);
//     const userId = req.user.id;
//     const { startDate, endDate } = req.body;

//     if (!startDate || !endDate) {
//         return res.status(400).json({ error: "Start date and end date are required." });
//     }

//     const recordsQuery = `
//       SELECT 
//           EMPLOYEE_ID, NAME, GROSSPAY, NET_PAY, FED_TAX, STATE_TAX, PAY_DATE
//       FROM payroll
//       WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?
//       ORDER BY EMPLOYEE_ID, PAY_DATE;
//     `;

//     const sumQuery = `
//       SELECT 
//           COALESCE(SUM(GROSSPAY), 0) AS totalGrossPay, 
//           COALESCE(SUM(NET_PAY), 0) AS totalNetPay, 
//           COALESCE(SUM(FED_TAX), 0) AS totalFedTax, 
//           COALESCE(SUM(STATE_TAX), 0) AS totalStateTax
//       FROM payroll
//       WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?;
//     `;

//     const businessQuery = `
//         SELECT name, b_stadd, b_suite, b_state, b_city, b_zip
//         FROM businesses
//         WHERE id = ?
//     `;

//     db.query(businessQuery, [businessId], async (businessErr, businessResults) => {
//         if (businessErr) {
//             console.error("Error fetching business data:", businessErr);
//             return res.status(500).json({ error: "Failed to fetch business data." });
//         }

//         if (businessResults.length === 0) {
//             return res.status(404).json({ error: "Business not found." });
//         }

//         const businessInfo = businessResults[0];

//         db.query(recordsQuery, [businessId, userId, startDate, endDate], async (err, records) => {
//             if (err) {
//                 console.error("Error fetching payroll data:", err);
//                 return res.status(500).json({ error: "Failed to fetch payroll data." });
//             }

//             if (records.length === 0) {
//                 return res.status(404).json({ error: "No payroll data found for the specified date range." });
//             }

//             db.query(sumQuery, [businessId, userId, startDate, endDate], async (sumErr, totals) => {
//                 if (sumErr) {
//                     console.error("Error calculating totals:", sumErr);
//                     return res.status(500).json({ error: "Failed to calculate payroll totals." });
//                 }

//                 const overallTotals = totals[0];

//                 // Group records by employee and calculate per-employee totals
//                 const groupedData = records.reduce((acc, record) => {
//                     if (!acc[record.NAME]) {
//                         acc[record.NAME] = { records: [], totals: { grossPay: 0, netPay: 0, federalTax: 0, stateTax: 0 } };
//                     }
//                     acc[record.NAME].records.push(record);
//                     acc[record.NAME].totals.grossPay += parseFloat(record.GROSSPAY || 0);
//                     acc[record.NAME].totals.netPay += parseFloat(record.NET_PAY || 0);
//                     acc[record.NAME].totals.federalTax += parseFloat(record.FED_TAX || 0);
//                     acc[record.NAME].totals.stateTax += parseFloat(record.STATE_TAX || 0);
//                     return acc;
//                 }, {});

//                 try {
//                     const { PDFDocument, rgb } = require("pdf-lib");
//                     const fs = require("fs");
//                     const pdfDoc = await PDFDocument.create();
//                     const logoBytes = fs.readFileSync("payweek.png"); // Replace with your logo path
//                     const logoImage = await pdfDoc.embedPng(logoBytes);
//                     const logoDimensions = logoImage.scale(0.08); // Adjust scale as needed

//                     let page = pdfDoc.addPage([600, 800]); // Letter size
//                     let y = 750;
//                     const fontSize = 10;

//                     // Helper to add a new page
//                     const addNewPage = () => {
//                         page = pdfDoc.addPage([600, 800]);
//                         y = 750;
//                         page.drawImage(logoImage, {
//                             x: 450,
//                             y: page.getHeight() - logoDimensions.height - 20,
//                             width: logoDimensions.width,
//                             height: logoDimensions.height,
//                         });
//                     };

//                     // Draw the logo on the first page
//                     page.drawImage(logoImage, {
//                         x: 450,
//                         y: page.getHeight() - logoDimensions.height - 20,
//                         width: logoDimensions.width,
//                         height: logoDimensions.height,
//                     });

//                     // Add Business Info on the top left of the first page
//                     page.drawText(businessInfo.name, { x: 50, y: 750, size: fontSize + 2, color: rgb(0, 0, 0) });
//                     page.drawText(`${businessInfo.b_stadd} ${businessInfo.b_suite || ""}`, { x: 50, y: 735, size: fontSize, color: rgb(0, 0, 0) });
//                     page.drawText(`${businessInfo.b_city}, ${businessInfo.b_state} ${businessInfo.b_zip}`, { x: 50, y: 720, size: fontSize, color: rgb(0, 0, 0) });

//                     y -= 50;

//                     // Add Title
//                     page.drawText(`Payroll Report for Business ID: ${businessId}`, { x: 50, y, size: fontSize + 4, color: rgb(0, 0, 0) });
//                     y -= 20;

//                     // Add Date Range
//                     page.drawText(`Date Range: ${startDate} - ${endDate}`, { x: 50, y, size: fontSize, color: rgb(0, 0, 0) });
//                     y -= 20;

//                     // Add Overall Totals
//                     page.drawText(`Overall Totals:`, { x: 50, y, size: fontSize + 2, color: rgb(0.2, 0.4, 0.8) });
//                     y -= 20;
//                     page.drawText(
//                         `Gross Pay: $${overallTotals.totalGrossPay}, Net Pay: $${overallTotals.totalNetPay}, Federal Tax: $${overallTotals.totalFedTax}, State Tax: $${overallTotals.totalStateTax}`,
//                         { x: 50, y, size: fontSize, color: rgb(0, 0, 0) }
//                     );
//                     y -= 30;

//                     // Add Employee Data
//                     Object.entries(groupedData).forEach(([employeeName, { records, totals }]) => {
//                         if (y < 50) addNewPage();

//                         // Employee Name
//                         page.drawText(`Employee: ${employeeName}`, { x: 50, y, size: fontSize + 2, color: rgb(0.2, 0.4, 0.8) });
//                         y -= 20;

//                         // Employee Totals
//                         page.drawText(
//                             `Totals - Gross Pay: $${totals.grossPay}, Net Pay: $${totals.netPay}, Federal Tax: $${totals.federalTax}, State Tax: $${totals.stateTax}`,
//                             { x: 50, y, size: fontSize, color: rgb(0, 0, 0) }
//                         );
//                         y -= 20;

//                         // Employee Records
//                         records.forEach((record) => {
//                             if (y < 50) addNewPage();

//                             page.drawText(
//                                 `Date: ${new Date(record.PAY_DATE).toLocaleDateString()}, Gross Pay: $${record.GROSSPAY}, Net Pay: $${record.NET_PAY}, Federal Tax: $${record.FED_TAX}, State Tax: $${record.STATE_TAX}`,
//                                 { x: 50, y, size: fontSize, color: rgb(0, 0, 0) }
//                             );
//                             y -= 20;
//                         });
//                         y -= 10;
//                     });

//                     // Serialize and send the PDF
//                     const pdfBytes = await pdfDoc.save();
//                     res.setHeader("Content-Type", "application/pdf");
//                     res.setHeader("Content-Disposition", `attachment; filename=payroll_${businessId}.pdf`);
//                     res.send(Buffer.from(pdfBytes));
//                 } catch (pdfErr) {
//                     console.error("Error generating PDF:", pdfErr);
//                     res.status(500).json({ error: "Failed to generate PDF." });
//                 }
//             });
//         });
//     });
// });




app.post("/payroll/pdf/:businessId", authenticateToken, async (req, res) => {
    const businessId = parseInt(req.params.businessId, 10);
    const userId = req.user.id;
    const { startDate, endDate } = req.body;

    if (!startDate || !endDate) {
        return res.status(400).json({ error: "Start date and end date are required." });
    }

    const recordsQuery = `
      SELECT 
          EMPLOYEE_ID, NAME, GROSSPAY, NET_PAY, FED_TAX, STATE_TAX, PAY_DATE
      FROM payroll
      WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?
      ORDER BY EMPLOYEE_ID, PAY_DATE;
    `;

    const sumQuery = `
      SELECT 
          COALESCE(SUM(GROSSPAY), 0) AS totalGrossPay, 
          COALESCE(SUM(NET_PAY), 0) AS totalNetPay, 
          COALESCE(SUM(FED_TAX), 0) AS totalFedTax, 
          COALESCE(SUM(STATE_TAX), 0) AS totalStateTax
      FROM payroll
      WHERE business_id = ? AND user_id = ? AND PAY_DATE BETWEEN ? AND ?;
    `;

    const businessQuery = `
        SELECT name, b_stadd, b_suite, b_state, b_city, b_zip
        FROM businesses
        WHERE id = ?
    `;

    db.query(businessQuery, [businessId], async (businessErr, businessResults) => {
        if (businessErr) {
            console.error("Error fetching business data:", businessErr);
            return res.status(500).json({ error: "Failed to fetch business data." });
        }

        if (businessResults.length === 0) {
            return res.status(404).json({ error: "Business not found." });
        }

        const businessInfo = businessResults[0];

        db.query(recordsQuery, [businessId, userId, startDate, endDate], async (err, records) => {
            if (err) {
                console.error("Error fetching payroll data:", err);
                return res.status(500).json({ error: "Failed to fetch payroll data." });
            }

            if (records.length === 0) {
                return res.status(404).json({ error: "No payroll data found for the specified date range." });
            }

            db.query(sumQuery, [businessId, userId, startDate, endDate], async (sumErr, totals) => {
                if (sumErr) {
                    console.error("Error calculating totals:", sumErr);
                    return res.status(500).json({ error: "Failed to calculate payroll totals." });
                }

                const overallTotals = totals[0];

                const groupedData = records.reduce((acc, record) => {
                    if (!acc[record.NAME]) {
                        acc[record.NAME] = { records: [], totals: { grossPay: 0, netPay: 0, federalTax: 0, stateTax: 0 } };
                    }
                    acc[record.NAME].records.push(record);
                    acc[record.NAME].totals.grossPay += parseFloat(record.GROSSPAY || 0);
                    acc[record.NAME].totals.netPay += parseFloat(record.NET_PAY || 0);
                    acc[record.NAME].totals.federalTax += parseFloat(record.FED_TAX || 0);
                    acc[record.NAME].totals.stateTax += parseFloat(record.STATE_TAX || 0);
                    return acc;
                }, {});

                try {
                    const { PDFDocument, rgb } = require("pdf-lib");
                    const fs = require("fs");
                    const pdfDoc = await PDFDocument.create();
                    const logoBytes = fs.readFileSync("payweek.png");
                    const logoImage = await pdfDoc.embedPng(logoBytes);
                    const logoDimensions = logoImage.scale(0.06);

                    let page = pdfDoc.addPage([600, 800]);
                    let y = 750;
                    const fontSize = 10;

                    const formatNumber = (value) => {
                        return new Intl.NumberFormat('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(value || 0);
                    };
                    

                    const addNewPage = () => {
                        page = pdfDoc.addPage([600, 800]);
                        y = 750;
                        page.drawImage(logoImage, {
                            x: 525,
                            y: page.getHeight() - logoDimensions.height - 15,
                            width: logoDimensions.width,
                            height: logoDimensions.height,
                        });
                    };

                    page.drawImage(logoImage, {
                        x: 525,
                        y: page.getHeight() - logoDimensions.height - 15,
                        width: logoDimensions.width,
                        height: logoDimensions.height,
                    });

                    page.drawText(businessInfo.name, { x: 50, y: 750, size: fontSize + 2, color: rgb(0, 0, 0) });
                    page.drawText(`${businessInfo.b_stadd} ${businessInfo.b_suite || ""}`, { x: 50, y: 735, size: fontSize, color: rgb(0, 0, 0) });
                    page.drawText(`${businessInfo.b_city}, ${businessInfo.b_state} ${businessInfo.b_zip}`, { x: 50, y: 720, size: fontSize, color: rgb(0, 0, 0) });

                    y -= 50;

                    page.drawText(`Payroll Report for Business ID: ${businessId}`, { x: 50, y, size: fontSize + 4, color: rgb(0, 0, 0) });
                    y -= 20;

                    page.drawText(`Date Range: ${startDate} - ${endDate}`, { x: 50, y, size: fontSize, color: rgb(0, 0, 0) });
                    y -= 20;

                    page.drawText(`Overall Totals:`, { x: 50, y, size: fontSize + 2, color: rgb(0.2, 0.4, 0.8) });
                    y -= 20;

                    page.drawText(`Gross Pay`, { x: 50, y, size: fontSize, color: rgb(0, 0, 0) });
                    page.drawText(`Net Pay`, { x: 150, y, size: fontSize, color: rgb(0, 0, 0) });
                    page.drawText(`Federal Tax`, { x: 250, y, size: fontSize, color: rgb(0, 0, 0) });
                    page.drawText(`State Tax`, { x: 350, y, size: fontSize, color: rgb(0, 0, 0) });
                    y -= 20;

                    page.drawText(`${overallTotals.totalGrossPay}`, { x: 50, y, size: fontSize, color: rgb(0, 0, 0) });
                    page.drawText(`${overallTotals.totalNetPay}`, { x: 150, y, size: fontSize, color: rgb(0, 0, 0) });
                    page.drawText(`${overallTotals.totalFedTax}`, { x: 250, y, size: fontSize, color: rgb(0, 0, 0) });
                    page.drawText(`${overallTotals.totalStateTax}`, { x: 350, y, size: fontSize, color: rgb(0, 0, 0) });
                    y -= 30;

                    Object.entries(groupedData).forEach(([employeeName, { records, totals }]) => {
                        if (y < 50) addNewPage();

                        page.drawText(`Employee: ${employeeName}`, { x: 50, y, size: fontSize + 2, color: rgb(0.2, 0.4, 0.8) });
                        y -= 20;

                        page.drawText(`Gross Pay`, { x: 150, y, size: fontSize, color: rgb(0, 0, 0) });
                        page.drawText(`Net Pay`, { x: 250, y, size: fontSize, color: rgb(0, 0, 0) });
                        page.drawText(`Federal Tax`, { x: 350, y, size: fontSize, color: rgb(0, 0, 0) });
                        page.drawText(`State Tax`, { x: 450, y, size: fontSize, color: rgb(0, 0, 0) });
                        y -= 20;

                           
                        console.log("Gross Pay");
                        console.log(totals.grossPay);

                        console.log("Net Pay");
                        console.log(totals.netPay);



                        // page.drawText(`${totals.grossPay}`, { x: 50, y, size: fontSize, color: rgb(0, 0, 0) });
                        // page.drawText(`${totals.netPay}`, { x: 150, y, size: fontSize, color: rgb(0, 0, 0) });
                        // page.drawText(`${totals.federalTax}`, { x: 250, y, size: fontSize, color: rgb(0, 0, 0) });
                        // page.drawText(`${totals.stateTax}`, { x: 350, y, size: fontSize, color: rgb(0, 0, 0) });
                        // y -= 20;

                        page.drawText("TOTAL", { x: 50, y, size: fontSize, color: rgb(0, 0, 0) });
                        page.drawText(formatNumber(totals.grossPay), { x: 150, y, size: fontSize, color: rgb(0, 0, 0) });
                        page.drawText(formatNumber(totals.netPay), { x: 250, y, size: fontSize, color: rgb(0, 0, 0) });
                        page.drawText(formatNumber(totals.federalTax), { x: 350, y, size: fontSize, color: rgb(0, 0, 0) });
                        page.drawText(formatNumber(totals.stateTax), { x: 450, y, size: fontSize, color: rgb(0, 0, 0) });
                        y -= 20;


                        
                            // page.drawText(`Gross Pay`, { x: 150, y, size: fontSize, color: rgb(0, 0, 0) });
                            // page.drawText(`Net Pay`, { x: 250, y, size: fontSize, color: rgb(0, 0, 0) });
                            // page.drawText(`Federal Tax`, { x: 350, y, size: fontSize, color: rgb(0, 0, 0) });
                            // page.drawText(`State Tax`, { x: 450, y, size: fontSize, color: rgb(0, 0, 0) });
                            // y -= 20;

                        records.forEach((record) => {
                            if (y < 50) addNewPage();

                            console.log(record.GROSSPAY);

                            page.drawText(`${record.PAY_DATE.toLocaleDateString()}`, { x: 50, y, size: fontSize, color: rgb(0, 0, 0) });
                            page.drawText(`${record.GROSSPAY}`, { x: 150, y, size: fontSize, color: rgb(0, 0, 0) });
                            page.drawText(`${record.NET_PAY}`, { x: 250, y, size: fontSize, color: rgb(0, 0, 0) });
                            page.drawText(`${record.FED_TAX || ""}`, { x: 350, y, size: fontSize, color: rgb(0, 0, 0) });
                            page.drawText(`${record.STATE_TAX || ""}`, { x: 450, y, size: fontSize, color: rgb(0, 0, 0) });
                            y -= 20;
                        });

                        y -= 10;
                    });

                    const pdfBytes = await pdfDoc.save();
                    res.setHeader("Content-Type", "application/pdf");
                    res.setHeader("Content-Disposition", `attachment; filename=payroll_${businessId}.pdf`);
                    res.send(Buffer.from(pdfBytes));
                } catch (pdfErr) {
                    console.error("Error generating PDF:", pdfErr);
                    res.status(500).json({ error: "Failed to generate PDF." });
                }
            });
        });
    });
});


app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
