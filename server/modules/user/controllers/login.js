const HTTPStatus = require('http-status');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const moment = require('moment');

const User = require('@User/model');
const AccessToken = require('@AccessToken/model');
const CONFIG = require('@CONFIG');
const APIError = require('@api-error');
const logger = require('@winston');

/**
 *  Returns jwt token and user details if valid email and password are provided
 * @property {string} req.body.email - The email of user.
 * @property {string} req.body.password - The password of user.
 * @returns {token, User}
 */
async function login(req, res, next) {
  const body = req.body;

  const validateData = () => {
    if (!body.email) {
      const err = new APIError('Email is required.', HTTPStatus.FORBIDDEN);
      throw err;
    }
    if (!body.password) {
      const err = new APIError('Password is required.', HTTPStatus.FORBIDDEN);
      throw err;
    }
  }

  const getAndValidateUser = async () => {
    let filter = {
      where: {
        email: body.email
      }
    }
    try {
      let userInstance = await User.findOne(filter);

      if (!userInstance) {
        const err = new APIError('User not registered.', HTTPStatus.UNAUTHORIZED);
        throw err;
      }
      if (!userInstance.comparePassword(body.password)) {
        const err = new APIError('User email and password combination do not match', HTTPStatus.UNAUTHORIZED);
        throw err;
      }

      return userInstance;
    } catch (exec) {
      throw exec;
    }
  }

  const createLoginToken = async (userData) => {
    let token = jwt.sign(userData, CONFIG.jwtSecret);
    let tokenData = {
      user_id: userData.id.toString(),
      token: token,
      expiry: moment().add(7, 'days').toISOString()
    }
    try {
      let loginToken = await AccessToken.create(tokenData);
      return loginToken;
    } catch (exec) {
      logger.error('ERROR > CREATING TOKEN > ', exec);
      throw exec;
    }
  }

  try {
    // VALIDATE BODY
    validateData();

    // GET AND VALIDATE USER
    let userInstance = await getAndValidateUser();

    // GENERATE LOGIN TOKEN
    let userData = _.pick(userInstance, ['id']);
    const loginToken = await createLoginToken(userData);

    return res.json({
      token: loginToken.token,
      user: userInstance.safeModel()
    });

  } catch (err) {
    logger.error('ERROR > USER SIGNIN > ', err);
    return next(err);
  }
}

module.exports = login;