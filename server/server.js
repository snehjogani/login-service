require('dotenv').config();
require('./alias');

// connect to db
const sequelize = require('@Sequelize')
sequelize.init();
const Sequelize = sequelize.get();

const express = require('express');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const expressValidation = require('express-validation');
const HTTPStatus = require('http-status');

const APIRoutes = require('@api');

const APIError = require('@api-error');

// config variables
const CONFIG = require('@CONFIG');

//LIB
const logger = require('@winston');

//Express
const app = express();

// Parse body params and attach them to req.body
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

app.use(cookieParser());
app.use(helmet());

app.use(cors());

// Server status CHECK
const START_TIME = Date.now()
app.get('/status-check', (req, res, next) => {
	const version = require('../package.json').version;
	res.status(200).json({
		version,
		startTime: START_TIME,
		upTime: Date.now() - START_TIME
	})
});

app.use('/api', APIRoutes);

// if error is not an instanceOf APIError, convert it.
app.use((err, req, res, next) => {
	if (err instanceof expressValidation.ValidationError) {
		// validation error contains errors which is an array of error each containing message[]
		const unifiedErrorMessage = err.errors.map(error => error.messages.join('. ')).join(' and ');
		return res.status(err.status).json({
			error: {
				message: unifiedErrorMessage,
				status: err.status,
				stack: CONFIG.env === 'development' ? err.stack : {}
			}
		});
	} else if (!(err instanceof APIError)) {
		return res.status(err.status || HTTPStatus.INTERNAL_SERVER_ERROR).json({
			error: {
				message: err.message,
				status: err.status || 500,
				stack: CONFIG.env === 'development' ? err.stack : {}
			},
			statusCode: err.status || 500
		});
	}
	return next(err);
});

// catch 404 and forward to error handler
app.use((req, res, next) => {
	const err = new APIError('API not found', HTTPStatus.NOT_FOUND);
	return next(err);
});

app.use((err, req, res, next) =>
	res.status(err.status).json({
		error: {
			message: err.message,
			status: err.status,
			stack: CONFIG.env === 'development' ? err.stack : {}
		},
		statusCode: err.status
	})
);

const start = () => {
	app.listen(CONFIG.port, (err) => {
		if (err) {
			logger.error(err);
			throw err;
		}
		logger.info(`Login service started on port ${CONFIG.port}`);
	});
}

Sequelize
	.authenticate()
	.then(() => {
		logger.info('Connection has been established successfully...');
		sequelize.associate();
		start();
	})
	.catch(err => {
		logger.error('Unable to connect to the database:', err);
	});


module.exports = app