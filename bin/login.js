'use strict';

const url = require('url');
const Saml = require('../lib/saml');
const rlex = require('../lib/extra-readline');
const CredentialsParser = require('../lib/credentials-parser');

/**
 * Login action
 * @param {Object} config
 */
function login(config) {
  const configObject = require(config.path);
  const { username, profile } = configObject;
  
  const saml = new Saml(configObject);
  const parser = new CredentialsParser();

  return askCredentials(username)
    .then(credentials => saml.login(credentials.username, credentials.password))
    .then(chooseAccount)
    .then(chosenAccount => {
      parser.updateProfile(profile, {
        aws_access_key_id: chosenAccount.AccessKeyId,
        aws_secret_access_key: chosenAccount.SecretAccessKey,
        aws_session_token: chosenAccount.SessionToken
      }).persist();

      console.log('Done!');
      process.exit(0);
    }).catch(err => {
      console.error(`Failed with error: ${err.message.trim()}`);
      process.exit(1);
    });
}

module.exports = login;

/**
 * Ask user's credentials
 * @returns {Promise}
 */
function askCredentials(username) {
  return new Promise(resolve => {
    rlex.resume();
    rlex.question(`Username (${username}): `, login => {
      rlex.secretQuestion('Password: ', password => {
        rlex.pause();

        resolve({ username: login || username, password: password });
      })
    });
  });
}

/**
 * Choose AWS account to login
 * @param {Array} accounts
 * @returns {Promise}
 */
function chooseAccount(accounts) {
  accounts.map((account, index) => {
    console.log(`[ ${index} ] ${account.Arn} (${account.name})`);
  });

  return new Promise(resolve => {
    rlex.resume();
    rlex.question('Choose account to login: ', index => {
      rlex.close();

      return resolve(accounts[index]);
    });
  });
}
