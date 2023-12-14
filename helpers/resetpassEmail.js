const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

const transporter = nodemailer.createTransport({
  service: 'Gmail', // Use your email service provider here
  auth: {
    user: process.env.AUTH_EMAIL, // Your email address
    pass: process.env.AUTH_PASS, // Your email password
  },
});

const resetpasswordreq = (user_email, resetToken) => {
  const mailOptions = {
    from: process.env.AUTH_EMAIL, // Your email address
    to: user_email, // Recipient's email address
    subject: 'Reset Password',
    text: `Click the following link to reset your password: http://localhost:3000/auth/resetpassword?token=${resetToken}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Email sending error:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

module.exports = resetpasswordreq;
