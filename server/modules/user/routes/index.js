const express = require('express');
const router = express.Router();
const controllers = require('@User/controllers');
const middleware = require('@middleware');

const middlewares = {
  logout: [middleware.isAuthenticated]
}

router.post('/login', controllers.login);

router.post('/logout', middlewares.logout, controllers.logout);

router.get('/', (req, res) => {
  res.status(200).send(`OK - ${req.baseUrl}`);
});

module.exports = router
