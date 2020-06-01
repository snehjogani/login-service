const Sequelize = require('sequelize');
const DataTypes = Sequelize.DataTypes;

const sequelize = require('@Sequelize').get();

const AccessToken = sequelize.define('access_token', {
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  token: {
    type: DataTypes.STRING,
    allowNull: false
  },
  expiry: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: new Date()
  },
}, {
  hooks: {
    beforeCount(options) {
      options.raw = true;
    }
  },
  tableName: 'access_token',
  paranoid: true,
  timestamps: true,
  underscored: true
})

AccessToken.associate = function (models) { // eslint-disable-line no-unused-vars
  // Define associations here
  // See http://docs.sequelizejs.com/en/latest/docs/associations/
  AccessToken.belongsTo(models.user, { as: 'user', foreignKey: 'user_id', targetKey: 'id', hooks: true });
};

module.exports = AccessToken;
