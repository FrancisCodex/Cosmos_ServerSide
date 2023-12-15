// middleware/verifyToken.js
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv'); // Import dotenv for environment variables
dotenv.config();

function verifyToken(req, res, next) {
    // Get the token from the request headers
    const authHeader = req.headers['authorization'];
  
    if (!authHeader) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
  
    // Check if the authorization header starts with "Bearer "
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Invalid authorization header' });
    }
  
    // Extract the token by removing the "Bearer " prefix
    const token = authHeader.substring(7); // Remove "Bearer " (7 characters)

    console.log('JWT Token:', token);
  
    // Verify the token
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {

        return res.status(403).json({ message: 'Forbidden' });
      }
      // If the token is valid, attach the user object to the request for later use
        req.user = user;
        
        console.log('Decoded User Data:', user);

        
      next(); // Proceed to the next middleware or route handler
    });
  }
  
  module.exports = verifyToken;