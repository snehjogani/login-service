const HTTPStatus = require('http-status');
const APIError = require('@api-error');
const jwt = require('jsonwebtoken');
const logger = require('@winston');
const moment = require('moment');
const CONFIG = require('@CONFIG');
const AccessToken = require('@AccessToken/model');
const User = require('@User/model');

const authentication = async (req, res, next) => {
  // extracting the token from request header
  let token = req.get('Authorization') || req.get('authorization') || req.query.access_token;
  if (!token) {
    req['isAuthenticated'] = false;
    return next();
  }
  token = token.replace('Bearer ', '');
  try {
    // checking whether token exists in the database or not
    let filter = { where: { token: token }, include: [{ model: User, as: 'user' }] }
    let accessToken = await AccessToken.findOne(filter);
    if (!accessToken) {
      req['isAuthenticated'] = false;
      return next();
    }
    // checking exipry of the token
    if (moment(accessToken.expiry).isBefore(moment())) {
      return next(new APIError('Your session has expired. Please login again!', HTTPStatus.UNAUTHORIZED));
    }
    // verifying the token against the one stored in the database
    let decoded = jwt.verify(token, CONFIG.jwtSecret);
    // forwarding the request with user data onto the detined request controller
    req['accessToken'] = {
      token,
      data: decoded || {},
      obj: accessToken
    };
    req['isAuthenticated'] = true;
    next();
  } catch (exec) {
    let message = 'Unauthorized!';
    if (exec.message && exec.message.indexOf('expired') > -1) {
      message = 'Your session has expired. Please login again!'
    }
    logger.error('INVALID TOKEN > ', exec);
    const err = new APIError(message, HTTPStatus.UNAUTHORIZED, true);
    return next(err);
  }
}

module.exports = authentication;