const moduleAlias = require('module-alias');

moduleAlias.addAliases({
  '@root': __dirname,
  '@api': __dirname + '/api',
  '@CONFIG': __dirname + '/config',
  '@middleware': __dirname + '/middleware',
  '@lib': __dirname + '/lib',
  '@api-error': __dirname + '/lib/api-error',
  '@winston': __dirname + '/lib/winston',
  '@Sequelize': __dirname + '/lib/sequelize',
  // modules-alias
  '@User': __dirname + '/modules/user',
  '@AccessToken': __dirname + '/modules/access-token'
})