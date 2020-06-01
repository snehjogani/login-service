const controllers = require('./controllers')
const routes = require('./routes')
const model = require('./model')

const User = {
  controllers,
  routes,
  model
}

module.exports = User