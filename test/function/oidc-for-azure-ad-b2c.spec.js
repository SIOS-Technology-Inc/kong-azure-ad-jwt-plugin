const chai = require('chai')
const expect = chai.expect
const jwt = require('jsonwebtoken')
const axios = require('axios')
const sleep = require('sleep')

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

describe('Azure AD B2C OIDCプラグインのプラグインの単体テスト', () => {
  before('kongのセッティング', async () => {
    const allRoutes = (await axios.get('http://localhost:8001/routes')).data.data
    await Promise.all(allRoutes.map(async route => {
      const allPlugins = (await axios.get(`http://localhost:8001/routes/${route.id}/plugins`)).data.data
      await Promise.all(allPlugins.map(async plugin => {
        await axios.delete(`http://localhost:8001/routes/${route.id}/plugins/${plugin.id}`)
      }))
      await axios.delete(`http://localhost:8001/routes/${route.id}`)
    }))
    const allConsumers = (await axios.get('http://localhost:8001/consumers')).data.data
    await Promise.all(allConsumers.map(async consumer => {
      await axios.delete(`http://localhost:8001/consumers/${consumer.id}`)
    }))
    const allServices = (await axios.get('http://localhost:8001/services')).data.data
    await Promise.all(allServices.map(async service => {
      await axios.delete(`http://localhost:8001/services/${service.id}`)
    }))

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
      name: 'oidc-for-azure-ad-b2c',
      config: {
        upstream_client_id: 'upstream_client_id'
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

    await sleep.sleep(1) // kongの設定反映待ち
  })
  describe('異常系テスト', () => {
    it('401: トークンが指定されていない場合エラーとなること', async () => {
      const res = await axios.get('http://localhost:8000/get', {
        headers: { Host: 'httpbin.org' },
        validateStatus: (status) => status < 500
      })
      expect(res.status).equal(401)
      expect(res.data.error_description).equal('The access token is missing')
      expect(res.data.error).equal('invalid_request')
    })
    it('401: トークンの有効期限が切れている場合エラーとなること', async () => {
      const jwtPayload = {
        extension_tenantId: 'testTenantId',
        oid: 'testId',
        extension_role: 'testRole'
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
    it('401: トークンのaudクレームがupstreamのクライアントIDと異なる場合場合エラーとなること', async () => {
      const jwtPayload = {
        extension_tenantId: 'testTenantId',
        oid: 'testId',
        extension_role: 'testRole',
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
    it('401: トークンが不正な場合エラーとなること', async () => {
      const res = await axios.get('http://localhost:8000/get', {
        headers: { Host: 'httpbin.org', Authorization: 'Bearer invalidToken' },
        validateStatus: (status) => status < 500
      })
      expect(res.status).equal(401)
      expect(res.data.error_description).equal('The access token is invalid')
      expect(res.data.error).equal('invalid_request')
    })
  })
  describe('正常系テスト', () => {
    describe('OAuth2プラグインでの認可失敗時のテスト', () => {
      let authorizationCodeToken
      let credentialsToken
      before('tokenの獲得', async () => {
        const jwtPayloadForAuthorizationCode = {
          extension_tenantId: 'testTenantId',
          oid: 'testId',
          extension_role: 'testRole',
          aud: 'upstream_client_id'
        }
        const jwtPayloadForClientCredentials = {
          azp: 'tenant_client_id',
          aud: 'upstream_client_id'
        }
        const jwtSecret = 'testSecretKey'
        const jwtOptions = {
          algorithm: 'HS256',
          expiresIn: '3m'
        }

        authorizationCodeToken = 'Bearer ' + jwt.sign(jwtPayloadForAuthorizationCode, jwtSecret, jwtOptions)

        credentialsToken = 'Bearer ' + jwt.sign(jwtPayloadForClientCredentials, jwtSecret, jwtOptions)
      })
      it('認可コードフローで正しくヘッダが返ってくること', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: authorizationCodeToken }
        })

        expect(res.status).equal(200)
        expect(res.data.headers).have.property('X-Bilink-Authenticated-Tenant-Id', 'testTenantId')
        expect(res.data.headers).have.property('X-Bilink-Authenticated-User-Id', 'testId')
        expect(res.data.headers).have.property('X-Bilink-Authenticated-User-Role', 'testRole')
        expect(res.data.headers).not.have.property('X-Consumer-Id')
        expect(res.data.headers).not.have.property('X-Consumer-Username')
        expect(res.data.headers).not.have.property('Authorization')
      })
      it('クライアントクレデンシャルズフローで正しくヘッダが返ってくること', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: credentialsToken },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(200)
        expect(res.data.headers).have.property('X-Bilink-Authenticated-Tenant-Id', 'testTenantId')
        expect(res.data.headers).not.have.property('X-Consumer-Id')
        expect(res.data.headers).not.have.property('X-Consumer-Username')
        expect(res.data.headers).not.have.property('Authorization')
      })
    })
    describe('OAuth2プラグインでの認可成功時のテスト', () => {
      let kongCredentialsToken
      let oauthPluginConsumerId
      before('コンシューマの登録とtokenの獲得', async () => {
        oauthPluginConsumerId = (await axios.post('http://localhost:8001/consumers', {
          username: 'testUsername'
        })).data.id

        await axios.post(`http://localhost:8001/consumers/${oauthPluginConsumerId}/oauth2`, {
          name: 'testApp',
          client_id: 'testClientId',
          client_secret: 'testClientSecret',
          redirect_uris: ['https://example.com']
        })
        await sleep.sleep(1)
        kongCredentialsToken = (await axios.post('https://localhost:8443/oauth2/token', {
          client_id: 'testClientId',
          client_secret: 'testClientSecret',
          grant_type: 'client_credentials'
        }, {
          headers: { Host: 'httpbin.org' }
        })).data.access_token
      })
      it('正しくヘッダが返ってくること', async () => {
        const res = await axios.get('http://localhost:8000/get', {
          headers: { Host: 'httpbin.org', Authorization: `Bearer ${kongCredentialsToken}` },
          validateStatus: (status) => status < 500
        })
        expect(res.status).equal(200)
        expect(res.data.headers).have.property('X-Consumer-Id', oauthPluginConsumerId)
        expect(res.data.headers).have.property('X-Consumer-Username', 'testUsername')
        expect(res.data.headers).not.have.property('X-Bilink-Authenticated-Tenant-Id')
        expect(res.data.headers).not.have.property('Authorization')
      })
    })
  })
})
