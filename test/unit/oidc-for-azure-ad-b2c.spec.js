const chai = require('chai')
const Plugin = require('../../plugins/oidc-for-azure-ad-b2c').Plugin
const expect = chai.expect
const jwt = require('jsonwebtoken')
const nock = require('nock')

class KongMock {
  constructor (headers) {
    this.logCalls = []
    this.errCalls = []
    this.warnCalls = []
    this.service = {}
    this.service.request = {
      setHeaderCalls: [],
      setHeader: (name, value) => {
        this.service.request.setHeaderCalls.push({ name, value })
      },
      clear_header: (hName) => {
        this.service.request.setHeaderCalls = this.service.request.setHeaderCalls.filter(setHeaderCall => setHeaderCall.name !== hName)
      }
    }
    this.request = {
      getHeader: (name) => {
        return headers[name]
      },
      headerCalls: [],
      set_header: (name, value) => {
        this.request.headerCalls.push({ name, value })
      },
      get_header: (name) => {
        return this.request.headerCalls.find(headerCall => headerCall.name === name).value
      }
    }
    this.response = {
      exitCalls: [],
      exit: (responseCode, responseBody) => {
        this.response.exitCalls.push({ responseCode, responseBody })
      }
    }
    this.log.err = (message) => {
      this.errCalls.push(message)
    }
    this.log.warn = (message) => {
      this.warnCalls.push(message)
    }
  }

  log (...messages) {
    this.logCalls.push(messages.join(' '))
  }
}

describe('Unit test for Azure AD B2C OIDC Plugin', () => {
  describe('Abnormal', () => {
    before('getting token', async () => {
      process.env.SIGNED_KEY = 'testSecretKey'
    })
    beforeEach('creating Graph API mock', () => {
      nock('https://login.microsoftonline.com')
        .post(uri => uri.includes('/token'))
        .reply(201, {
          token_type: 'Bearer',
          expires_in: 3599,
          access_token: 'token'
        })
      nock('https://graph.microsoft.com')
        .get(uri => uri.includes('/v1.0/applications'))
        .reply(200, {
          value: [{
            displayName: 'testTenantId'
          }]
        })
    })
    it('throws a 401 error when no access token is provided', async () => {
      const mock = new KongMock({ Authorization: null })
      const plugin = new Plugin()
      mock.request.set_header('X-Anonymous-Consumer', 'true')
      mock.service.request.setHeader('X-Consumer-Id', 'testId')
      mock.service.request.setHeader('X-Consumer-Username', 'anonymous_users')
      await plugin.access(mock)
      expect(mock.response.exitCalls[0].responseCode).equal(401)
      expect(mock.response.exitCalls[0].responseBody).to.deep.contain({
        error_description: 'The access token is missing',
        error: 'invalid_request'
      })
    })
    it('throws a 401 error when the access token is expired', async () => {
      const jwtPayload = {
        iss: 'https://test.b2clogin.com',
        tenantId: 'testTenantId',
        id: 'testId',
        role: 'testRole'
      }
      const jwtSecret = 'testSecretKey'
      const jwtOptions = {
        algorithm: 'HS256',
        expiresIn: '0s'
      }

      const expiredToken = 'Bearer ' + jwt.sign(jwtPayload, jwtSecret, jwtOptions)

      const mock = new KongMock({ Authorization: expiredToken })
      const plugin = new Plugin({
        upstream_client_id: 'upstream_client_id'
      })
      mock.request.set_header('X-Anonymous-Consumer', 'true')
      mock.service.request.setHeader('X-Consumer-Id', 'testId')
      mock.service.request.setHeader('X-Consumer-Username', 'anonymous_users')
      await plugin.access(mock)
      expect(mock.response.exitCalls[0].responseCode).equal(401)
      expect(mock.response.exitCalls[0].responseBody).to.deep.contain({
        error_description: 'The access token is expired',
        error: 'invalid_request'
      })
    })
    it('throws a 401 error when the aud claim does NOT equal "config.upstream_client_id"', async () => {
      const jwtPayload = {
        tenantId: 'testTenantId',
        id: 'testId',
        role: 'testRole',
        aud: 'invalid'
      }
      const jwtSecret = 'testSecretKey'
      const jwtOptions = {
        algorithm: 'HS256',
        expiresIn: '3m'
      }

      const invalidAudToken = 'Bearer ' + jwt.sign(jwtPayload, jwtSecret, jwtOptions)

      const mock = new KongMock({ Authorization: invalidAudToken })
      const plugin = new Plugin({
        upstream_client_id: 'client_id'
      })
      mock.request.set_header('X-Anonymous-Consumer', 'true')
      mock.service.request.setHeader('X-Consumer-Id', 'testId')
      mock.service.request.setHeader('X-Consumer-Username', 'anonymous_users')
      await plugin.access(mock)
      expect(mock.response.exitCalls[0].responseCode).equal(401)
      expect(mock.response.exitCalls[0].responseBody).to.deep.contain({
        error_description: 'The access token is invalid',
        error: 'invalid_request'
      })
      expect(mock.warnCalls[0]).to.include('JsonWebTokenError')
      expect(mock.warnCalls[1]).to.include('jwt audience invalid')
      expect(mock.warnCalls[2]).to.include('"JsonWebTokenError: jwt audience invalid.')
    })
    it('throws a 401 error when the access token is invalid', async () => {
      const mock = new KongMock({ Authorization: 'Bearer invalidToken' })
      const plugin = new Plugin({
        upstream_client_id: 'upstream_client_id'
      })
      mock.request.set_header('X-Anonymous-Consumer', 'true')
      mock.service.request.setHeader('X-Consumer-Id', 'testId')
      mock.service.request.setHeader('X-Consumer-Username', 'anonymous_users')
      await plugin.access(mock)
      expect(mock.response.exitCalls[0].responseCode).equal(401)
      expect(mock.response.exitCalls[0].responseBody).to.deep.contain({
        error_description: 'The access token is invalid',
        error: 'invalid_request'
      })
      expect(mock.warnCalls[0]).to.include('invalid JWT format')
    })
    it('throws a 500 error when system error is occurred', async () => {
      const mock = new KongMock()
      const plugin = new Plugin()
      mock.request = null // Make the request null and intentionally give an error
      await plugin.access(mock)
      expect(mock.response.exitCalls[0].responseCode).equal(500)
      expect(mock.response.exitCalls[0].responseBody).to.deep.contain({
        error_description: 'Unknown_error',
        error: 'Unknown_error'
      })
      expect(mock.errCalls[1]).to.include('Cannot read property \'getHeader\' of null')
      expect(mock.errCalls[2]).to.include('TypeError: Cannot read property \'getHeader\' of null')
    })
  })

  describe('Normal', () => {
    let authorizationCodeToken
    let credentialsToken
    before('getting token', async () => {
      const jwtPayloadForAuthorizationCode = {
        iss: 'https://test.b2clogin.com/',
        extension_tenantId: 'testTenantId',
        oid: 'testId',
        extension_role: 'testRole',
        aud: 'upstream_client_id'
      }
      const jwtPayloadForClientCredentials = {
        iss: 'https://login.microsoftonline.com/',
        aud: 'upstream_client_id',
        azp: 'tenant_client_id'
      }
      const jwtSecret = 'testSecretKey'
      process.env.SIGNED_KEY = 'testSecretKey'
      const jwtOptions = {
        algorithm: 'HS256',
        expiresIn: '3m'
      }

      authorizationCodeToken = 'Bearer ' + jwt.sign(jwtPayloadForAuthorizationCode, jwtSecret, jwtOptions)

      credentialsToken = 'Bearer ' + jwt.sign(jwtPayloadForClientCredentials, jwtSecret, jwtOptions)
    })

    beforeEach('creating Graph API mock', () => {
      nock('https://login.microsoftonline.com')
        .post(uri => uri.includes('/token'))
        .reply(201, {
          token_type: 'Bearer',
          expires_in: 3599,
          access_token: 'token'
        })
        .post(uri => uri.includes('/token'))
        .reply(201, {
          token_type: 'Bearer',
          expires_in: 3599,
          access_token: 'token'
        })
      nock('https://graph.microsoft.com')
        .get(uri => uri.includes('/v1.0/users'))
        .reply(200, {
          value: [{}]
        })
      nock('https://graph.microsoft.com')
        .get(uri => uri.includes('/v1.0/applications'))
        .reply(200, {
          value: [{
            displayName: 'testTenantId'
          }]
        })
    })

    it('returns right headers for the upstream server when using authorization code flows', async () => {
      const mock = new KongMock({ Authorization: authorizationCodeToken })
      const plugin = new Plugin({
        upstream_client_id: 'upstream_client_id',
        authorization_code: {
          header_mapping: {
            'X-Bilink-Authenticated-Tenant-Id': { from: 'token', value: 'extension_tenantId' },
            'X-Bilink-Authenticated-User-Id': { from: 'token', value: 'oid' },
            'X-Bilink-Authenticated-User-Role': { from: 'token', value: 'extension_role' }
          }
        },
        client_credentials: {
          header_mapping: { 'X-Bilink-Authenticated-Tenant-Id': { from: 'client', value: 'displayName' } }
        }
      })
      mock.request.set_header('X-Anonymous-Consumer', 'true')
      mock.service.request.setHeader('X-Consumer-Id', 'testId')
      mock.service.request.setHeader('X-Consumer-Username', 'anonymous_users')
      await plugin.access(mock)
      expect(mock.service.request.setHeaderCalls[0]).to.deep.equal({
        name: 'X-Bilink-Authenticated-Tenant-Id',
        value: 'testTenantId'
      })
      expect(mock.service.request.setHeaderCalls[1]).to.deep.equal({
        name: 'X-Bilink-Authenticated-User-Id',
        value: 'testId'
      })
      expect(mock.service.request.setHeaderCalls[2]).to.deep.equal({
        name: 'X-Bilink-Authenticated-User-Role',
        value: 'testRole'
      })
    })
    it('returns right headers for the upstream server when using client credentials flows', async () => {
      const mock = new KongMock({ Authorization: credentialsToken })
      const plugin = new Plugin({
        upstream_client_id: 'upstream_client_id',
        authorization_code: {
          header_mapping: {
            'X-Bilink-Authenticated-Tenant-Id': { from: 'token', value: 'extension_tenantId' },
            'X-Bilink-Authenticated-User-Id': { from: 'token', value: 'oid' },
            'X-Bilink-Authenticated-User-Role': { from: 'token', value: 'extension_role' }
          }
        },
        client_credentials: {
          header_mapping: { 'X-Bilink-Authenticated-Tenant-Id': { from: 'client', value: 'displayName' } }
        }
      })
      mock.request.set_header('X-Anonymous-Consumer', 'true')
      mock.service.request.setHeader('X-Consumer-Id', 'testId')
      mock.service.request.setHeader('X-Consumer-Username', 'anonymous_users')
      await plugin.access(mock)
      expect(mock.service.request.setHeaderCalls[0]).to.deep.equal({
        name: 'X-Bilink-Authenticated-Tenant-Id',
        value: 'testTenantId'
      })
    })
    it('skips when "X-Anonymous-Consumer" from oauth2 plugin is false', async () => {
      const mock = new KongMock({ Authorization: credentialsToken })
      const plugin = new Plugin({
        upstream_client_id: 'upstream_client_id',
        authorization_code: {
          header_mapping: {
            'X-Bilink-Authenticated-Tenant-Id': { from: 'token', value: 'extension_tenantId' },
            'X-Bilink-Authenticated-User-Id': { from: 'token', value: 'oid' },
            'X-Bilink-Authenticated-User-Role': { from: 'token', value: 'extension_role' }
          }
        },
        client_credentials: {
          header_mapping: { 'X-Bilink-Authenticated-Tenant-Id': { from: 'client', value: 'displayName' } }
        }
      })
      mock.request.set_header('X-Anonymous-Consumer', 'false')
      mock.service.request.setHeader('X-Consumer-Id', 'testId')
      mock.service.request.setHeader('X-Consumer-Username', 'not_anonymous_users')
      await plugin.access(mock)
      expect(mock.service.request.setHeaderCalls[0]).to.deep.equal({
        name: 'X-Consumer-Id',
        value: 'testId'
      })
      expect(mock.service.request.setHeaderCalls[1]).to.deep.equal({
        name: 'X-Consumer-Username',
        value: 'not_anonymous_users'
      })
      mock.service.request.setHeaderCalls.map(header => expect(header).to.not.have.property('name', 'X-Bilink-Authenticated-Tenant-Id'))
    })
  })
})
