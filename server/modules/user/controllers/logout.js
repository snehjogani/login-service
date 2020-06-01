const _ = require('lodash');
const HTTPStatus = require('http-status');

const AccessToken = require('@AccessToken/model');
const APIError = require('@api-error');
const logger = require('@winston')

async function logout(req, res, next) {
  if (!req.isAuthenticated) {
    const err = new APIError('Unauthenticated', HTTPStatus.UNAUTHORIZED, true);
    return next(err);
  }

  let accessTokenId = req.accessToken.obj.dataValues.id

  try {
    let filter = {
      where: {
        id: accessTokenId
      }
    }

    let accessToken = await AccessToken.destroy(filter)

    return res.json({
      message: "Logout successful!"
    })

  } catch (err) {
    logger.error('ERROR > CREATING TOKEN > ', err);
    return next(err);
  }
}

module.exports = logout;