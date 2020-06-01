const authentication = require('./authentication');
const isAuthenticated = require('./is-authenticated');

const middleware = {
  authentication,
  isAuthenticated,
}

module.exports = middleware;