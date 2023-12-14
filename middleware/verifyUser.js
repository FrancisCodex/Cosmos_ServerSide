const verifyUser = async (req, res, next) => {
    if (!req.user || !req.user.is_verified) {
      return res.status(403).json({ message: 'Access denied. Please verify your email.' });
    }
    next();
  };