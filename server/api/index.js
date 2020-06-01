const express = require('express');
const apiRoutes = express()

const middleware = require('@middleware');

const UserRoutes = require('@User/routes')

apiRoutes.get('/', (req, res) => {
  res.status(200).send(`OK - ${req.baseUrl}`)
})

apiRoutes.use('/', middleware.authentication);
apiRoutes.use('/users', UserRoutes)

module.exports = apiRoutes