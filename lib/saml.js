'use strict';

const url = require('url');
const sax = require('sax');
const fetch = require('cross-fetch');
const STS = require('aws-sdk/clients/sts');
const FormData = require('form-data');

let config;

// Node side compatibility
const https = require('https');

const agent = https ? new https.Agent({
  rejectUnauthorized: false,
}) : undefined;

class Saml {
  /**
   * @param {Object} params
   * @param {String} params.directoryDomain - Directory domain (eg. https://sts.mycorp.com)
   * @param {String?} params.username - Default username
   * @param {String} params.domain - Domain for authentication (eg. CORP)
   * @param {Object?} params.accountMapping - Account mapping object (key: accountId, value: accountName)
   */
  constructor(params) {
    config = params;

    const idpEntryUrl = url.resolve(config.directoryDomain, 'adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices');
    let idp = url.parse(idpEntryUrl);

    this._parser = sax.parser(false, { lowercase: true });
    this._domain = `${idp.protocol}//${idp.host}`;
    this._entryPath = idp.path;
    this._samlResponse = null;
  }

  /**
   * Get login path (w/o domain)
   * @returns {Promise}
   */
  getLoginPath() {
    let loginPath = '';
    let initUrl = url.resolve(this._domain, this._entryPath);

    return new Promise((resolve, reject) => {
      fetch(initUrl, { agent })
        .then(res => res.text())
        .then((body) => {
          this._parser.onopentag = node => {
            if (node.name === 'form' && node.attributes.id === 'loginForm') {
              loginPath = node.attributes.action;
            }
          };

          this._parser.onerror = err => reject(err);
          this._parser.onend = () => resolve(loginPath);
          this._parser.write(body).close();
        })
        .catch(err => reject(err));
    });
  }

  /**
   * @param {String} loginPath
   * @param {String} username
   * @param {String} password
   * @returns {Promise}
   * @private
   */
  _login(loginPath, username, password) {
    return new Promise((resolve, reject) => {
      const form = new FormData();
      form.append('UserName', `CORP\\${username}`);
      form.append('Password', password);
      form.append('AuthMethod', '');
      form.append('Kmsi', true);

      fetch(url.resolve(this._domain, loginPath), {
        method: 'POST',
        agent,
        body: form,
      })
        .then(res => res.text())
        .then(body => {
          let samlResponse = '';
          let errorText = '';

          this._parser.onopentag = node => {
            if (node.name === 'input' && node.attributes.name === 'SAMLResponse') {
              samlResponse = node.attributes.value;
            }

            if (node.attributes.id === 'errorText') {
              let dirtyError = body.substr(this._parser.position, 300);
              let matched = dirtyError.match(/^(.*)<\//);
              errorText = matched ? matched[1] : dirtyError;
            }
          };

          this._parser.onerror = err => reject(err);
          this._parser.onend = () => {
            if (errorText) {
              return reject(new Error(errorText));
            }

            resolve(samlResponse);
          };
          this._parser.write(body).close();
      })
        .catch(err => Promise.reject(err));
    });
  }

  /**
   * Get login SAML Response as base64 string
   * @param {String} loginPath
   * @param {String} username
   * @param {String} password
   * @returns {Promise}
   */
  getSamlResponse(loginPath, username, password) {
    if (this._samlResponse) {
      return Promise.resolve(this._samlResponse);
    }

    return this._login(loginPath, username, password).then(samlResponse => {
      this._samlResponse = samlResponse;

      return samlResponse;
    });
  }

  /**
   * Parse SAML Response
   * @param {String} samlResponse
   * @returns {String}
   */
  static parseSamlResponse(samlResponse) {
    return Buffer.from(samlResponse, 'base64').toString('utf8');
  }

/**
 *
 *
 * @param {any} username
 * @param {any} password
 * @returns {Promise} containing accounts
 */
  async login(username, password) {
    const samlLoginPath = await this.getLoginPath();

    let samlRawResponse;
    return this.getSamlResponse(samlLoginPath, username, password)
      .then(samlResponse => {
        samlRawResponse = samlResponse;
        return parseRoles(samlResponse);
      })
      .then(roles =>
          Promise.all(roles.map(role => assumeRole(role.roleArn, role.principalArn, samlRawResponse)))
            .then(results => results.filter(Boolean))
      ).then(accounts => {
        const accountsList = accounts.map((account, index) => {
          let [, accountId] = account.Arn.match(/(\d+):role/);

          return {
            Arn: account.Arn,
            name: config.accountMapping[accountId] || accountId,
          }
        });
        return Promise.resolve(accountsList);
      });
  }
}

/**
 * Parse role ARNs from xmlSamlResponse
 * @param {String} samlRawResponse
 * @returns {Promise}
 */
async function parseRoles(samlRawResponse) {
  const samlResponse = Saml.parseSamlResponse(samlRawResponse);

  return new Promise((resolve, reject) => {
    let roles = [];
    let parser = sax.parser(false);

    parser.ontext = text => {
      if (/^arn:aws:iam::.*/.test(text)) {
        const [principalArn, roleArn] = text.split(',');

        roles.push({ principalArn, roleArn });
      }
    };

    parser.onerror = err => reject(err);
    parser.onend = () => resolve(roles);
    parser.write(samlResponse).close();
  })
}


/**
 * Assume role (resolve false on fail)
 * @param {String} roleArn
 * @param {String} principalArn
 * @param {String} samlResponse
 * @returns {Promise}
 */
function assumeRole(roleArn, principalArn, samlResponse) {
  const sts = new STS();
  const params = { RoleArn: roleArn, PrincipalArn: principalArn, SAMLAssertion: samlResponse };

  return sts
    .assumeRoleWithSAML(params)
    .promise()
    .then(data => {
      return Promise.resolve(
        Object.assign({ Arn: roleArn }, data.Credentials)
      );
    })
    .catch((err) => {
      Promise.resolve(false)
    });
}

module.exports = Saml;
