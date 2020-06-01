const Sequelize = require('sequelize');
const DataTypes = Sequelize.DataTypes;
const bcrypt = require('bcryptjs');
const _ = require('lodash');
const sequelize = require('@Sequelize').get();
const CONFIG = require('@CONFIG');

const User = sequelize.define('user', {
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isEmail: true,
    },
    unique: false
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  },
  topic: {
    type: DataTypes.STRING,
    allowNull: true
  }
}, {
  hooks: {
    beforeCount(options) {
      options.raw = true;
    }
  },
  tableName: 'user',
  paranoid: true,
  timestamps: true,
  underscored: true
})

User.associate = function (models) { // eslint-disable-line no-unused-vars
  // Define associations here
  // See http://docs.sequelizejs.com/en/latest/docs/associations/
};

/**
 * Hash the plain password
 * @param {String} plain - Plain password.
 * @returns {String} - Hashed password.
 */
const hashPassword = (plain) => {
  const salt = bcrypt.genSaltSync(CONFIG.SALT_WORK_FACTOR);
  return bcrypt.hashSync(plain, salt);
}

User.hashPassword = hashPassword;

User.beforeCreate((user, options) => {
  user.password = hashPassword(user.password);
  return user;
});

User.beforeUpdate((user, options) => {
  if (user.changed('password')) {
    user.password = hashPassword(user.password);
  }
  return user;
});

User.prototype.safeModel = function (ignoreFields = ['password']) {
  let user = this;
  let userData = _.omit(user.dataValues, ignoreFields);
  return userData;
}

function comparePassword(plain) {
  const user = this;
  return bcrypt.compareSync(plain, user.password);
}

User.prototype.comparePassword = comparePassword;

module.exports = User;
