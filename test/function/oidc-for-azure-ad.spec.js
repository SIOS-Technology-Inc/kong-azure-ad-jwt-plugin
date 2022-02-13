const chai = require('chai')
const expect = chai.expect
const jwt = require('jsonwebtoken')
const axios = require('axios')
const sleep = require('sleep')
const { reset } = require('../utils/kong')

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

describe('Function test for Azure AD OIDC Plugin', () => {
  describe('Abnormal', () => {
    describe('when Kong Auth Plugin is NOT used', () => {
      before('clear', reset)
      before('setting kong', async () => {
        await axios.post('http://localhost:8001/services', {
          name: 'httpbin',
          url: 'http://kong-upstream-server'
        })
        await axios.post('http://localhost:8001/services/httpbin/routes', {
          hosts: ['httpbin.org'],
          name: 'httpbin-route',
          protocols: ['http'],
          strip_path: false
        })
        await axios.post('http://localhost:8001/routes/httpbin-route/plugins', {
          name: 'oidc-for-azure-ad',
          config: {
            upstream_client_id: 'upstream_client_id',
            kong_client_id: 'client_id',
            kong_client_secret: 'client_secret',
            azure_tenant: 'test.example.com',
            jwks_url: 'http://example.com',
            header_mapping: {
              'X-Authenticated-Client-Id': { from: 'token', value: 'azp' },
              'X-Authenticated-Client-Name': { from: 'client', value: 'displayName', encode: 'url_encode' }
            }
          }
        })

        await sleep.sleep(1) // Wait for the kong settings to be reflected
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
        const jwtSecret = 'testSecretKey'
        const jwtOptions = {
          algorithm: 'HS256',
          expiresIn: '0s'
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
        const jwtSecret = 'testSecretKey'
        const jwtOptions = {
          algorithm: 'HS256',
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
      before('clear', reset)
      before('setting kong', async () => {
        await axios.post('http://localhost:8001/services', {
          name: 'httpbin',
          url: 'http://kong-upstream-server'
        })
        await axios.post('http://localhost:8001/services/httpbin/routes', {
          hosts: ['httpbin.org'],
          name: 'httpbin-route',
          protocols: ['http'],
          strip_path: false
        })
        const oauthPluginId = (await axios.post('http://localhost:8001/routes/httpbin-route/plugins', {
          name: 'oauth2',
          config: {
            enable_client_credentials: true
          },
          enabled: true
        })).data.id
        await axios.post('http://localhost:8001/routes/httpbin-route/plugins', {
          name: 'oidc-for-azure-ad',
          config: {
            upstream_client_id: 'upstream_client_id',
            kong_client_id: 'client_id',
            kong_client_secret: 'client_secret',
            azure_tenant: 'test.example.com',
            jwks_url: 'http://example.com',
            header_mapping: {
              'X-Authenticated-Client-Id': { from: 'token', value: 'azp' },
              'X-Authenticated-Client-Name': { from: 'client', value: 'displayName', encode: 'url_encode' }
            }
          }
        })
        const anonymousConsumerId = (await axios.post('http://localhost:8001/consumers', {
          username: 'anonymous_users'
        })).data.id
        await axios.patch(`http://localhost:8001/plugins/${oauthPluginId}`, {
          config: {
            anonymous: anonymousConsumerId
          }
        })

        await sleep.sleep(1) // Wait for the kong settings to be reflected
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
        const jwtSecret = 'testSecretKey'
        const jwtOptions = {
          algorithm: 'HS256',
          expiresIn: '0s'
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
        const jwtSecret = 'testSecretKey'
        const jwtOptions = {
          algorithm: 'HS256',
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
      before('clear', reset)
      before('setting kong', async () => {
        await axios.post('http://localhost:8001/services', {
          name: 'httpbin',
          url: 'http://kong-upstream-server'
        })
        await axios.post('http://localhost:8001/services/httpbin/routes', {
          hosts: ['httpbin.org'],
          name: 'httpbin-route',
          protocols: ['http'],
          strip_path: false
        })
        await axios.post('http://localhost:8001/routes/httpbin-route/plugins', {
          name: 'oidc-for-azure-ad',
          config: {
            upstream_client_id: 'upstream_client_id',
            kong_client_id: 'client_id',
            kong_client_secret: 'client_secret',
            azure_tenant: 'test.example.com',
            jwks_url: 'http://example.com',
            header_mapping: {
              'X-Authenticated-Client-Id': { from: 'token', value: 'azp' },
              'X-Authenticated-Client-Name': { from: 'client', value: 'displayName', encode: 'url_encode' }
            }
          }
        })

        await sleep.sleep(1) // Wait for the kong settings to be reflected
      })
      let credentialsToken
      before('getting token', async () => {
        const jwtPayloadForClientCredentials = {
          iss: 'https://login.microsoftonline.com/',
          aud: 'upstream_client_id',
          azp: 'clientId'
        }
        const jwtSecret = 'testSecretKey'
        const jwtOptions = {
          algorithm: 'HS256',
          expiresIn: '3m'
        }

        credentialsToken = 'Bearer ' + jwt.sign(jwtPayloadForClientCredentials, jwtSecret, jwtOptions)
      })
      it('returns right headers for the upstream server when using client credentials flows', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: credentialsToken },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(200)
        expect(res.data.headers).to.have.property('X-Authenticated-Client-Id', 'clientId')
        expect(res.data.headers).to.have.property('X-Authenticated-Client-Name', 'clientName')
        expect(res.data.headers).not.have.property('X-Consumer-Id')
        expect(res.data.headers).not.have.property('X-Consumer-Username')
        expect(res.data.headers).not.have.property('Authorization')
      })
    })
    describe('when an access token is NOT allowed at OAuth2 Plugin', () => {
      before('clear', reset)
      before('setting kong', async () => {
        await axios.post('http://localhost:8001/services', {
          name: 'httpbin',
          url: 'http://kong-upstream-server'
        })
        await axios.post('http://localhost:8001/services/httpbin/routes', {
          hosts: ['httpbin.org'],
          name: 'httpbin-route',
          protocols: ['http'],
          strip_path: false
        })
        const oauthPluginId = (await axios.post('http://localhost:8001/routes/httpbin-route/plugins', {
          name: 'oauth2',
          config: {
            enable_client_credentials: true
          },
          enabled: true
        })).data.id
        await axios.post('http://localhost:8001/routes/httpbin-route/plugins', {
          name: 'oidc-for-azure-ad',
          config: {
            upstream_client_id: 'upstream_client_id',
            kong_client_id: 'client_id',
            kong_client_secret: 'client_secret',
            azure_tenant: 'test.example.com',
            jwks_url: 'http://example.com',
            header_mapping: {
              'X-Authenticated-Client-Id': { from: 'token', value: 'azp' },
              'X-Authenticated-Client-Name': { from: 'client', value: 'displayName', encode: 'url_encode' }
            }
          }
        })
        const anonymousConsumerId = (await axios.post('http://localhost:8001/consumers', {
          username: 'anonymous_users'
        })).data.id
        await axios.patch(`http://localhost:8001/plugins/${oauthPluginId}`, {
          config: {
            anonymous: anonymousConsumerId
          }
        })

        await sleep.sleep(1) // Wait for the kong settings to be reflected
      })
      let credentialsToken
      before('getting token', async () => {
        const jwtPayloadForClientCredentials = {
          iss: 'https://login.microsoftonline.com/',
          aud: 'upstream_client_id',
          azp: 'clientId'
        }
        const jwtSecret = 'testSecretKey'
        const jwtOptions = {
          algorithm: 'HS256',
          expiresIn: '3m'
        }

        credentialsToken = 'Bearer ' + jwt.sign(jwtPayloadForClientCredentials, jwtSecret, jwtOptions)
      })
      it('returns right headers for the upstream server when using client credentials flows', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: credentialsToken },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(200)
        expect(res.data.headers).to.have.property('X-Authenticated-Client-Id', 'clientId')
        expect(res.data.headers).to.have.property('X-Authenticated-Client-Name', 'clientName')
        expect(res.data.headers).not.have.property('X-Consumer-Id')
        expect(res.data.headers).not.have.property('X-Consumer-Username')
        expect(res.data.headers).not.have.property('Authorization')
      })
    })
    describe('when an access token is allowed at OAuth2 Plugin', () => {
      before('clear', reset)
      before('setting kong', async () => {
        await axios.post('http://localhost:8001/services', {
          name: 'httpbin',
          url: 'http://kong-upstream-server'
        })
        await axios.post('http://localhost:8001/services/httpbin/routes', {
          hosts: ['httpbin.org'],
          name: 'httpbin-route',
          protocols: ['http'],
          strip_path: false
        })
        const oauthPluginId = (await axios.post('http://localhost:8001/routes/httpbin-route/plugins', {
          name: 'oauth2',
          config: {
            enable_client_credentials: true
          },
          enabled: true
        })).data.id
        await axios.post('http://localhost:8001/routes/httpbin-route/plugins', {
          name: 'oidc-for-azure-ad',
          config: {
            upstream_client_id: 'upstream_client_id',
            kong_client_id: 'client_id',
            kong_client_secret: 'client_secret',
            azure_tenant: 'test.example.com',
            use_kong_auth: true,
            jwks_url: 'http://example.com',
            header_mapping: {
              'X-Authenticated-Client-Id': { from: 'token', value: 'azp' },
              'X-Authenticated-Client-Name': { from: 'client', value: 'displayName', encode: 'url_encode' }
            }
          }
        })
        const anonymousConsumerId = (await axios.post('http://localhost:8001/consumers', {
          username: 'anonymous_users'
        })).data.id
        await axios.patch(`http://localhost:8001/plugins/${oauthPluginId}`, {
          config: {
            anonymous: anonymousConsumerId
          }
        })

        await sleep.sleep(1) // Wait for the kong settings to be reflected
      })
      let kongCredentialsToken
      let oauthPluginConsumerId
      before('creating kong consumer and getting token', async () => {
        try {
          oauthPluginConsumerId = (await axios.post('http://localhost:8001/consumers', {
            username: 'testUsername'
          })).data.id

          await axios.post(`http://localhost:8001/consumers/${oauthPluginConsumerId}/oauth2`, {
            name: 'testApp',
            client_id: 'testClientId',
            client_secret: 'testClientSecret',
            redirect_uris: ['https://example.com']
          })
          await sleep.sleep(2)
          kongCredentialsToken = (await axios.post('https://localhost:8443/oauth2/token', {
            client_id: 'testClientId',
            client_secret: 'testClientSecret',
            grant_type: 'client_credentials'
          }, {
            headers: { Host: 'httpbin.org' }
          })).data.access_token
        } catch (e) {
          console.log(e)
          throw e
        }
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
