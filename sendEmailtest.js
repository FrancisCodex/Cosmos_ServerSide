const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
dotenv.config();

// Create a nodemailer transporter with your email service provider's SMTP settings
const transporter = nodemailer.createTransport({
  service: 'Gmail', // Use your email service provider here
  host: '',
  auth: {
    user: process.env.AUTH_EMAIL, // Your email address
    pass: process.env.AUTH_PASS, // Your email password
  },
});

// Email content
const mailOptions = {
  from: process.env.AUTH_EMAIL, // Your email address
  to: 'francisadrian.altesing@gmail.com', // Your Gmail address
  subject: 'Test Email', // Email subject
  text: 'This is a test email from Nodemailer.', // Email message
};

// Send the email
transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    console.error('Email sending error:', error);
  } else {
    console.log('Email sent:', info.response);
  }
});
