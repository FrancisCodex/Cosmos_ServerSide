const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
dotenv.config();

// Function to send OTP to user's email
const sendOTPEmail = async (email, otp) => {
  let transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: process.env.AUTH_EMAIL,
      pass: process.env.AUTH_PASS, 
    }
  });

  let mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: 'Your OTP',
    text: `Your OTP is ${otp}`
  };

  transporter.sendMail(mailOptions, function(error, info){
    if (error) {
      console.log(error);
    } else {
      console.log('Email sent: ' + info.response);
    }
  });
};


module.exports = sendOTPEmail;