const express = require('express');
const router = express.Router();
const auth = require('../controllers/auth');
const verifyToken = require('../middleware/verifyToken');
const pool = require('../config/database');
const resetpasswordreq = require('../helpers/resetpassEmail');
const crypto = require('crypto');

// Define the login route
router.post('/login', auth.login);

// Define the registration route
router.post('/register', auth.register);

// Define the email verification route
router.get('/verify', auth.verify);

//Resetpassword route
router.post('/resetPassword', auth.resetPassword);

//Check Reset Token
router.post('/checkResetToken', auth.checkResetToken);

//generate otp route
router.post('/generateOTP', auth.generateOTP);

//verify otp route
router.post('/verifyOTP', auth.verifyOTP);

router.get('/logout', auth.logout);

router.get('/userdata', verifyToken, async (req, res) => {
  try {
    // Fetch user data from your database using req.user.userId
    const userData = await pool.query('SELECT name, user_email, is_verified FROM cosmos.users WHERE user_id = $1', [req.user.userId]);

    if (userData.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Extract user's name, email, and verification status from the database query result
    const { name, user_email, is_verified } = userData.rows[0];

    res.status(200).json({ user: { name, email: user_email, is_verified } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/reset-password-request', async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the user with the provided email exists in the database
    const user = await pool.query('SELECT * FROM cosmos.users WHERE user_email = $1', [email]);

    if (user.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const userRecord = user.rows[0];

    // Generate a reset token (you can use a library like `crypto`)
    const resetToken = crypto.randomBytes(32).toString('hex');

    // Update the user's record in the database with the reset token and expiration time
    await pool.query('UPDATE cosmos.users SET reset_token = $1 WHERE user_id = $2', [
      resetToken,
      userRecord.user_id,
    ]);

    // Send an email to the user with a link containing the resetToken

    // You can use a function like your `sendVerificationEmail` for this purpose
    resetpasswordreq(email, resetToken);


    res.status(200).json({ success: true, message: 'Password reset email sent successfully' });
  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


router.post('/test', auth.test);

module.exports = router;
