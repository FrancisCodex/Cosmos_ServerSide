
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const pool = require('../config/database')
const dotenv = require('dotenv');
const cookie = require('cookie');
const sendVerificationEmail = require('../helpers/email');
const sendOTPEmail = require('../helpers/sendotp');
const crypto = require('crypto');


dotenv.config();




//FUNCTIONS

//random generation verification
const generateVerificationToken = () => {
  // Generate a random token here
  const verificationToken = crypto.randomBytes(32).toString('hex');
  return verificationToken;
};

async function logAction(action, user_id, details) {
  try {
    await pool.query('INSERT INTO cosmos.audit_logs (log_action, user_id, details) VALUES ($1, $2, $3)', [action, user_id, details]);
  } catch (error) {
    console.error(error);
  }
}

const generateOTP = () => {
  const otp = Math.floor(100000 + Math.random() * 900000); // generates a six digit number
  return otp;
};

const algorithm = 'aes-256-ctr';
const secretKey = process.env.RANDOM_SECRETKEY; // generate a secure secret key
const iv = crypto.randomBytes(16);

const encrypt = (text) => {
  const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return encrypted.toString('hex');
};


//END OF FUNCTIONS


// Login controller
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user exists in the database
    const userQueryResult = await pool.query('SELECT * FROM cosmos.users WHERE user_email = $1', [email]);

    if (userQueryResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = userQueryResult.rows[0];

    // Compare the entered password with the hashed password in the database
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Check the otp_token table for the user's OTP validity
    const otpQueryResult = await pool.query('SELECT * FROM cosmos.otp_token WHERE user_id = $1', [user.user_id]);

    if (otpQueryResult.rows.length === 0 || otpQueryResult.rows[0].otp_validity === null) {
      return res.status(200).json({ message: 'OTP is expired' });
    }

    const otpRecord = otpQueryResult.rows[0];

    // Check if the OTP validity has expired
    const otpValidityInDays = (Date.now() - new Date(otpRecord.otp_validity)) / (1000 * 60 * 60 * 24);
    if (otpValidityInDays > 10) {
      return res.status(200).json({ message: 'OTP is expired' });
    }

    // Generate and send a JSON web token (JWT) for authentication
    const token = jwt.sign({ userId: user.user_id }, process.env.JWT_SECRET, {
      expiresIn: '1h', // Adjust the expiration time as needed
    });

    // Set the token in a cookie
    res.setHeader(
      'Set-Cookie',
      cookie.serialize('token', token, {
        httpOnly: true,
        maxAge: 3600, // Token expiration time in seconds (1 hour in this example)
        sameSite: 'none', // Adjust this based on your security requirements
        secure: false, // Set secure to true in production
        path: '/', // Specify the path where the cookie is accessible
      })
    );

    await logAction('User Login', user.user_id, `User logged in with ID: ${user.user_id}`);

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.logout = async (req, res) => {
  // Get the token from the cookies
  const token = req.cookies.token;

  // If the token is not found, return an error
  if (!token) {
    return res.status(404).send('User already logged out, no Token Found');
  }

  console.log("what is the token", token);

  // Decode the token to get the userId
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId;

  console.log("what is the userId", userId);

  // Perform the logAction
  await logAction('User Logout', userId, `User logged out with ID: ${userId}`);

  // Clear the cookie
  res.clearCookie('token').send('You are now logged out');
}

exports.register = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if the email already exists in the database
    const existingUser = await pool.query('SELECT * FROM cosmos.users WHERE user_email = $1', [email]);

    if (existingUser.rows.length > 0) {
      // Email already exists, return a 400 Bad Request response
      return res.status(400).json({ success: false, message: 'Email already exists' });
    }

    // Hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate a verification token
    const verificationToken = generateVerificationToken();

    // Insert the new user into the database with verification token
    await pool.query(
      'INSERT INTO cosmos.users (name, user_email, password, verification_token) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, email, hashedPassword, verificationToken]
    );

    const user = await pool.query('SELECT * FROM cosmos.users WHERE user_email = $1', [email]);
    
    const user_id = user.rows[0].user_id;
    // Send a verification email to the user
    sendVerificationEmail(email, verificationToken);

    const otp = generateOTP();
    
    const otpExpiration = new Date();
    otpExpiration.setMinutes(otpExpiration.getMinutes() + 30);

    await pool.query('INSERT INTO cosmos.otp_token (user_id, otp_token, otp_expiration) VALUES ($1, $2, $3) RETURNING *', [user_id, otp, otpExpiration]);
    
    
    sendOTPEmail(email, otp);
    
    await logAction('User Registration', user_id, `User registered with ID: ${user_id}`);
    // Send a successful registration response
    res.status(201).json({ success: true, message: 'User registered successfully', validation: 'OTP sent to email' });

  } catch (error) {
    console.error('Registration error:', error);

    // Handle other errors (e.g., validation errors) here
    res.status(422).json({ success: false, message: 'Validation failed' });
  }
};


// Generate OTP API Call
exports.generateOTP = async (req, res) => {
  const { email } = req.body;

  try {
    // Find the user with the matching email in the database
    const user = await pool.query('SELECT * FROM cosmos.users WHERE user_email = $1', [email]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userRecord = user.rows[0];

    // Generate an OTP
    const otp = generateOTP();

    const otpExpiration = new Date();
    otpExpiration.setMinutes(otpExpiration.getMinutes() + 10);  

    //otp_validity should be 10 days
    const otpValidity = new Date();
    otpValidity.setDate(otpValidity.getDate() + 10);

    // Store the OTP in the database
    await pool.query('UPDATE cosmos.otp_token SET otp_token = $1, otp_expiration = $2 WHERE user_id = $3', [otp, otpExpiration, userRecord.user_id]);

    // Send the OTP to the user's email
    
    sendOTPEmail(email, otp);

    res.status(200).json({ message: 'OTP generated and sent to email' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};




// RESET PASSWORD API CALL
exports.resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    // Find the user with the matching reset token in the database
    const user = await pool.query('SELECT * FROM cosmos.users WHERE reset_token = $1', [token]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'Invalid or expired token' });
    }

    const userRecord = user.rows[0];
    // const currentTimestamp = Date.now();

    // // Check if the reset token has expired
    // if (userRecord.reset_token_expires < currentTimestamp) {
    //   return res.status(401).json({ message: 'Token has expired' });
    // }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the reset token in the database
    await pool.query('UPDATE cosmos.users SET password = $1, reset_token = null WHERE user_id = $2', [hashedPassword, userRecord.user_id]);

    await logAction('Password Reset', userRecord.user_id, `User reset password with ID: ${userRecord.user_id}`);


    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Verify a user's email
exports.verify = async (req, res) => {
  const { token } = req.query;

  try {
    // Find the user with the matching verification token in the database
    const user = await pool.query('SELECT * FROM cosmos.users WHERE verification_token = $1', [token]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'Invalid or expired token' });
    }

    // Mark the user's account as verified
    await pool.query('UPDATE cosmos.users SET is_verified = true, verification_token = null WHERE user_id = $1', [user.rows[0].user_id]);

    res.status(200).json({ message: 'Account verified successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Verify OTP API Call
exports.verifyOTP = async (req, res) => {
  const { otp, email } = req.body;

  try {
    // Find the user with the matching email in the database
    const user = await pool.query('SELECT * FROM cosmos.users WHERE user_email = $1', [email]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userRecord = user.rows[0];

    const user_id = userRecord.user_id;

    const otpQueryResult = await pool.query('SELECT * FROM cosmos.otp_token WHERE user_id = $1', [user_id]);
    console.log("what is the otpQueryResult", otpQueryResult.rows[0])

    console.log("what is the otp", otp);
    //check if the otp is expired
    if (otpQueryResult.rows[0].otp_expiration < Date.now()) {
      return res.status(401).json({ message: 'OTP has expired' });
    }
    
    if (otpQueryResult.rows[0].otp_token !== otp) {
      return res.status(401).json({ message: 'Invalid OTP' });
    }

    //otp_validity should be 10 days
    const otpValidity = new Date();
    otpValidity.setDate(otpValidity.getDate() + 10);


    // If OTP matches, clear the OTP from the database
    await pool.query('UPDATE cosmos.otp_token SET otp_token = null, otp_validity = $1 WHERE user_id = $2', [otpValidity, userRecord.user_id]);

    // Generate and send a JSON web token (JWT) for authentication
    const token = jwt.sign({ userId: userRecord.user_id }, process.env.JWT_SECRET, {
      expiresIn: '1h', // Adjust the expiration time as needed
    });

    // Set the token in a cookie
    res.setHeader(
      'Set-Cookie',
      cookie.serialize('token', token, {
        httpOnly: true,
        maxAge: 3600, // Token expiration time in seconds (1 hour in this example)
        sameSite: 'none', // Adjust this based on your security requirements
        secure: false, // Set secure to true in production
        path: '/', // Specify the path where the cookie is accessible
      })
    );

    res.status(200).json({ message: 'OTP verified successfully', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// check the validity of the reset token

exports.checkResetToken = async (req, res) => {
  // get the token in params
  const { token } = req.body;
  console.log("what is the token", token);
  try{
    // check if the token is valid
    const user = await pool.query('SELECT * FROM cosmos.users WHERE reset_token = $1', [token]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'Invalid or expired token' });
    }

    const userRecord = user.rows[0];
    const currentTimestamp = Date.now();

    // // Check if the reset token has expired
    // if (userRecord.reset_token_expires < currentTimestamp) {
    //   return res.status(401).json({ message: 'Token has expired' });
    // }

    res.status(200).json({ message: 'Token is valid' });
  }catch(error){
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }


};


exports.test = (req, res) => {
  const {card_number, card_cvv} = req.body;

  console.log("what is the card number", card_number);
  

  try{
    const encryptedCardNumber = encrypt(card_number);
    const encryptedCardCVV = encrypt(card_cvv);

    console.log("what is the encrypted card number", encryptedCardNumber);
    console.log("what is the encrypted card cvv", encryptedCardCVV);
    res.status(200).json({ message: 'Test successful', encryptedCardNumber, encryptedCardCVV});
  }
  catch(error){
    res.status(500).json({ message: 'Internal server error' });
  }
}
