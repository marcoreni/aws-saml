'use strict';

const url = require('url');
const sax = require('sax');
const fetch = process.env.WEBPACK_BUILD ? require('cross-fetch') : require('fetch-cookie/node-fetch')(require('cross-fetch'));
const STS = require('aws-sdk/clients/sts');

let config;

// Node side compatibility
const https = require('https');

const agent = process.env.WEBPACK_BUILD ? undefined: new https.Agent({
  rejectUnauthorized: false,
});

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

    return fetch(initUrl, { agent })
      .then(res => res.text())
      .then((body) => {
        return new Promise((resolve, reject) => {
          this._parser.onopentag = node => {
            if (node.name === 'form' && node.attributes.id === 'loginForm') {
              loginPath = node.attributes.action;
            }
          };

          this._parser.onerror = err => reject(err);
          this._parser.onend = () => resolve(loginPath);
          this._parser.write(body).close();
        });
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
    const targetUrl = url.resolve(this._domain, loginPath);
    const form = new url.URLSearchParams();
    form.append('UserName', `${config.domain}\\${username}`);
    form.append('Password', password);
    form.append('AuthMethod', '');
    form.append('Kmsi', true);

    return fetch(targetUrl, {
      method: 'POST',
      agent,
      body: form,
      credentials: 'include',
    })
      .then(res => res.text())
      .then(body => {
        return new Promise((resolve, reject) => {
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
  authenticate(username, password) {
    let samlRawResponse;

    return this.getLoginPath()
      .then(samlLoginPath => this.getSamlResponse(samlLoginPath, username, password))
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
function parseRoles(samlRawResponse) {
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
