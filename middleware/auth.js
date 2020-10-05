const jwt = require('jsonwebtoken');

const checkToken = (req, res, next) => {
  let token = req.headers['x-access-token'] || req.headers.authorization;
 
    // Remove Bearer from string
    token = token.split(' ')[1];

  if (token) {
    jwt.verify(token, 'secret', (err, decoded) => {
      if (err) {
        return res.status(403).json({
          message: "Invalid Access Token",
        });
      }
      req.decoded = decoded;
      next();
    });
  } else {
    return res.status(401).json({
      success: false,
      message: "Access Token Required",
    });
  }
};

module.exports = checkToken;