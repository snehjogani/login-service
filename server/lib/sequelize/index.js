const Sequelize = require('sequelize');
const CONFIG = require('@CONFIG');
const DATABASE = CONFIG.database;
const operatorsAliases = require('./sequelize-operators-alias');

let instance;

const init = () => {
  instance = new Sequelize({
    host: DATABASE.host,
    username: DATABASE.username,
    password: DATABASE.password,
    database: DATABASE.name,
    dialect: DATABASE.dialect,
    port: DATABASE.port,
    logging: false,
    operatorsAliases,
    define: {
      freezeTableName: true
    }
  });
}

const get = () => {
  if (!instance) {
    throw Error('Not yet initialized');
  }
  return instance;
}

const associate = () => {
  if (!instance) {
    throw Error('Not yet initialized');
  }

  // Set up data relationships
  const models = instance.models;
  Object.keys(models).forEach(name => {
    if ('associate' in models[name]) {
      models[name].associate(models);
    }
  });

  // Sync to the database
  instance.sync();
}

const sequelize = {
  init,
  get,
  associate
}

module.exports = sequelize;