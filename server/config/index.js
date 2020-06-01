const config = {
  host: process.env.HOST || 'http://localhost',
  port: process.env.PORT || '3000',
  jwtSecret: process.env.JWT_SECRET || '0a6b944d-d2fb-46fc-a85e-0295c986cd9f',
  jwtExpiry: process.env.JWT_EXPIRY || '7 days',
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || '3306',
    username: process.env.DB_USERNAME || 'root',
    password: process.env.DB_PASSWORD || '',
    name: process.env.DB_NAME || 'assignment2',
    dialect: 'mysql'
  },
}

module.exports = config