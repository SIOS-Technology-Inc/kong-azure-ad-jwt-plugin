const chai = require('chai')
const expect = chai.expect
const fs = require('fs')
const jwt = require('jsonwebtoken')
const axios = require('axios')
const axiosRetry = require('axios-retry')
const uuid = require('uuid')
const kong = require('../utils/kong')
const { httpbinService, httpbinRoute, oidcForAzureADB2CPlugin } = require('../kong-setting')

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
const jwtSecret = fs.readFileSync('./test/stub/azure-ad-b2c-jwks-api/private.pem')

describe('Function test for Azure AD B2C OIDC Plugin', () => {
  describe('Abnormal', () => {
    describe('when Kong Auth Plugin is NOT used', () => {
      before('setting kong', async () => {
        await kong.reset()
        await kong.sync({
          services: [
            {
              ...httpbinService,
              routes: [
                {
                  ...httpbinRoute,
                  plugins: [oidcForAzureADB2CPlugin]
                }
              ]
            }
          ]
        })
      })
      it('throws a 401 error when no access token is provided', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org' },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(401)
        expect(res.data.error_description).equal('The access token is missing')
        expect(res.data.error).equal('invalid_request')
      })
      it('throws a 401 error when the access token is expired', async () => {
        const jwtPayload = {
          iss: 'https://test.b2clogin.com/',
          sub: 'userId',
          aud: 'upstream_client_id',
          azp: 'clientId'
        }
        const jwtOptions = {
          algorithm: 'RS256',
          expiresIn: '-1s'
        }
        const expiredToken = 'Bearer ' + jwt.sign(jwtPayload, jwtSecret, jwtOptions)

        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: expiredToken },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(401)
        expect(res.data.error_description).equal('The access token is expired')
        expect(res.data.error).equal('invalid_request')
      })
      it('throws a 401 error when the aud claim does NOT equal "config.upstream_client_id"', async () => {
        const jwtPayload = {
          iss: 'https://test.b2clogin.com/',
          sub: 'userId',
          azp: 'clientId',
          aud: 'invalid'
        }
        const jwtOptions = {
          algorithm: 'RS256',
          expiresIn: '3m'
        }
        const invalidAudToken = 'Bearer ' + jwt.sign(jwtPayload, jwtSecret, jwtOptions)

        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: `Bearer ${invalidAudToken}` },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(401)
        expect(res.data.error_description).equal('The access token is invalid')
        expect(res.data.error).equal('invalid_request')
      })
      it('throws a 401 error when the access token is invalid', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: 'Bearer invalidToken' },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(401)
        expect(res.data.error_description).equal('The access token is invalid')
        expect(res.data.error).equal('invalid_request')
      })
    })
    describe('when Kong Auth Plugin is used', () => {
      before('setting kong', async () => {
        const anonymousId = uuid.v4()
        await kong.reset()
        await kong.sync({
          consumers: [
            {
              id: anonymousId,
              username: 'anonymous_users'
            }
          ],
          services: [
            {
              ...httpbinService,
              routes: [
                {
                  ...httpbinRoute,
                  plugins: [
                    {
                      name: 'oauth2',
                      config: {
                        enable_client_credentials: true,
                        anonymous: anonymousId,
                        provision_key: 'dummy'
                      },
                      enabled: true
                    },
                    oidcForAzureADB2CPlugin
                  ]
                }
              ]
            }
          ]
        })
      })
      it('throws a 401 error when no access token is provided', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org' },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(401)
        expect(res.data.error_description).equal('The access token is missing')
        expect(res.data.error).equal('invalid_request')
      })
      it('throws a 401 error when the access token is expired', async () => {
        const jwtPayload = {
          iss: 'https://test.b2clogin.com/',
          sub: 'userId',
          aud: 'upstream_client_id',
          azp: 'clientId'
        }
        const jwtOptions = {
          algorithm: 'RS256',
          expiresIn: '-1s'
        }
        const expiredToken = 'Bearer ' + jwt.sign(jwtPayload, jwtSecret, jwtOptions)

        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: expiredToken },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(401)
        expect(res.data.error_description).equal('The access token is expired')
        expect(res.data.error).equal('invalid_request')
      })
      it('throws a 401 error when the aud claim does NOT equal "config.upstream_client_id"', async () => {
        const jwtPayload = {
          iss: 'https://test.b2clogin.com/',
          sub: 'userId',
          azp: 'clientId',
          aud: 'invalid'
        }
        const jwtOptions = {
          algorithm: 'RS256',
          expiresIn: '3m'
        }
        const invalidAudToken = 'Bearer ' + jwt.sign(jwtPayload, jwtSecret, jwtOptions)

        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: `Bearer ${invalidAudToken}` },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(401)
        expect(res.data.error_description).equal('The access token is invalid')
        expect(res.data.error).equal('invalid_request')
      })
      it('throws a 401 error when the access token is invalid', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: 'Bearer invalidToken' },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(401)
        expect(res.data.error_description).equal('The access token is invalid')
        expect(res.data.error).equal('invalid_request')
      })
    })
  })
  describe('Normal', () => {
    describe('when Kong Auth Plugin is NOT used', () => {
      before('setting kong', async () => {
        await kong.reset()
        await kong.sync({
          services: [
            {
              ...httpbinService,
              routes: [
                {
                  ...httpbinRoute,
                  plugins: [oidcForAzureADB2CPlugin]
                }
              ]
            }
          ]
        })
      })
      let authorizationCodeToken
      before('getting token', async () => {
        const jwtPayloadForAuthorizationCode = {
          iss: 'https://test.b2clogin.com/',
          sub: 'userId',
          aud: 'upstream_client_id',
          azp: 'clientId',
          name: 'name'
        }
        const jwtOptions = {
          algorithm: 'RS256',
          expiresIn: '3m'
        }

        authorizationCodeToken = 'Bearer ' + jwt.sign(jwtPayloadForAuthorizationCode, jwtSecret, jwtOptions)
      })
      it('returns right headers for the upstream server when using authorization code flows', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: authorizationCodeToken }
        })

        expect(res.status).equal(200)
        expect(res.data.headers).to.have.property('X-Authenticated-Client-Id', 'clientId')
        expect(res.data.headers).to.have.property('X-Authenticated-Client-Name', 'clientName')
        expect(res.data.headers).to.have.property('X-Authenticated-User-Id', 'userId')
        expect(res.data.headers).to.have.property('X-Authenticated-User-Name', 'userName')
        expect(res.data.headers).not.have.property('X-Consumer-Id')
        expect(res.data.headers).not.have.property('X-Consumer-Username')
        expect(res.data.headers).not.have.property('Authorization')
      })
    })
    describe('when an access token is NOT allowed at OAuth2 Plugin', () => {
      before('setting kong', async () => {
        const anonymousId = uuid.v4()
        await kong.reset()
        await kong.sync({
          consumers: [
            {
              id: anonymousId,
              username: 'anonymous_users'
            }
          ],
          services: [
            {
              ...httpbinService,
              routes: [
                {
                  ...httpbinRoute,
                  plugins: [
                    {
                      name: 'oauth2',
                      config: {
                        enable_client_credentials: true,
                        anonymous: anonymousId,
                        provision_key: 'dummy'
                      },
                      enabled: true
                    },
                    oidcForAzureADB2CPlugin
                  ]
                }
              ]
            }
          ]
        })
      })
      let authorizationCodeToken
      before('getting token', async () => {
        const jwtPayloadForAuthorizationCode = {
          iss: 'https://test.b2clogin.com/',
          sub: 'userId',
          aud: 'upstream_client_id',
          azp: 'clientId',
          name: 'name'
        }
        const jwtOptions = {
          algorithm: 'RS256',
          expiresIn: '3m'
        }

        authorizationCodeToken = 'Bearer ' + jwt.sign(jwtPayloadForAuthorizationCode, jwtSecret, jwtOptions)
      })
      it('returns right headers for the upstream server when using authorization code flows', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: authorizationCodeToken }
        })

        expect(res.status).equal(200)
        expect(res.data.headers).to.have.property('X-Authenticated-Client-Id', 'clientId')
        expect(res.data.headers).to.have.property('X-Authenticated-Client-Name', 'clientName')
        expect(res.data.headers).to.have.property('X-Authenticated-User-Id', 'userId')
        expect(res.data.headers).to.have.property('X-Authenticated-User-Name', 'userName')
        expect(res.data.headers).not.have.property('X-Consumer-Id')
        expect(res.data.headers).not.have.property('X-Consumer-Username')
        expect(res.data.headers).not.have.property('Authorization')
      })
    })
    describe('when an access token is allowed at OAuth2 Plugin', () => {
      const oauthPluginConsumerId = uuid.v4()
      before('setting kong', async () => {
        const anonymousId = uuid.v4()
        await kong.reset()
        await kong.sync({
          consumers: [
            {
              id: anonymousId,
              username: 'anonymous_users'
            },
            {
              id: oauthPluginConsumerId,
              username: 'testUsername',
              oauth2_credentials: [
                {
                  name: 'testApp',
                  client_id: 'testClientId',
                  client_secret: 'testClientSecret',
                  redirect_uris: ['https://example.com']
                }
              ]
            }
          ],
          services: [
            {
              ...httpbinService,
              routes: [
                {
                  ...httpbinRoute,
                  plugins: [
                    {
                      name: 'oauth2',
                      config: {
                        enable_client_credentials: true,
                        anonymous: anonymousId,
                        provision_key: 'dummy'
                      },
                      enabled: true
                    },
                    {
                      ...oidcForAzureADB2CPlugin,
                      config: {
                        ...oidcForAzureADB2CPlugin.config,
                        use_kong_auth: true
                      }
                    }
                  ]
                }
              ]
            }
          ]
        })
      })
      let kongCredentialsToken
      before('creating kong consumer and getting token', async () => {
        const client = axios.create({ baseURL: 'https://localhost:8443' })
        axiosRetry(client, {
          retries: 5,
          retryDelay: axiosRetry.exponentialDelay,
          retryCondition: (error) => error.response.status >= 300
        })
        kongCredentialsToken = (await client.post('https://localhost:8443/oauth2/token', {
          client_id: 'testClientId',
          client_secret: 'testClientSecret',
          grant_type: 'client_credentials'
        }, {
          headers: { Host: 'httpbin.org' }
        })).data.access_token
      })
      it('returns right headers for the upstream server', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: `Bearer ${kongCredentialsToken}` },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(200)
        expect(res.data.headers).have.property('X-Consumer-Id', oauthPluginConsumerId)
        expect(res.data.headers).have.property('X-Consumer-Username', 'testUsername')
        expect(res.data.headers).not.to.have.property('X-Authenticated-Client-Id')
        expect(res.data.headers).not.to.have.property('X-Authenticated-Client-Name')
      })
    })
  })
})
