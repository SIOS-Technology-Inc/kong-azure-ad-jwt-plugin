require('isomorphic-fetch')
const mgclient = require('@microsoft/microsoft-graph-client')
const jwksClient = require('jwks-rsa')
const jwt = require('jsonwebtoken')
const axios = require('axios')
const parseBearerToken = require('parse-bearer-token').default

const verifyJWT = (token, getKey, verifyOptions) => {
  return new Promise((resolve, reject) =>
    jwt.verify(token, getKey, verifyOptions, (err, decoded) => {
      return resolve({ err, decoded })
    })
  )
}
const getSigningKey = (client, kid) => {
  return new Promise((resolve, reject) => {
    client.getSigningKey(kid, function (err, key) {
      if (err) {
        return reject(err)
      }
      return resolve({ err, signingKey: key.publicKey || key.rsaPublicKey })
    })
  })
}
class OidcForAzureADB2CPlugin {
  constructor (config) {
    this.config = config
    this.graphApiClientID = process.env.CLIENT_ID_FOR_MS_GRAPH_API
    this.graphApiClientSecret = process.env.CLIENT_SECRET_FOR_MS_GRAPH_API
    this.graphApiTenantId = process.env.TENANT_ID_FOR_MS_GRAPH_API
    const authorizationCodeJwksUrl = process.env.AUTHORIZATION_CODE_JWKS_URL
    const clientCredentialsJwksUrl = process.env.CLIENT_CREDENTIALS_JWKS_URL
    this.graphApiBaseUrl = process.env.GRAPH_API_URL || 'https://graph.microsoft.com'
    this.graphApiLoginUrl = process.env.GRAPH_API_LOGIN_URL || 'https://login.microsoftonline.com'
    this.authorizationCodeJwksClient = jwksClient({
      jwksUri: authorizationCodeJwksUrl,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 600000 // 10min
    })
    this.clientCredentialsJwksClient = jwksClient({
      jwksUri: clientCredentialsJwksUrl,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 600000 // 10min
    })
  }

  async buildGraghapiClient () {
    const getAccessTokenFunc = async () => {
      const params = new URLSearchParams()
      params.append('client_id', this.graphApiClientID)
      params.append('client_secret', this.graphApiClientSecret)
      params.append('scope', 'https://graph.microsoft.com/.default')
      params.append('grant_type', 'client_credentials')
      return (await axios.post(`${this.graphApiLoginUrl}/${this.graphApiTenantId}/oauth2/v2.0/token`, params)).data.access_token
    }

    // When the access token expires, it will be automatically reacquired.
    this.graphApiClient = mgclient.Client.initWithMiddleware({
      authProvider: {
        getAccessToken: getAccessTokenFunc
      }
    })
    this.graphApiClient.config.baseUrl = this.graphApiBaseUrl
  }

  async access (kong) {
    try {
      const headerToken = await kong.request.getHeader('Authorization')
      await kong.service.request.clear_header('Authorization')
      if ((await kong.request.get_header('X-Anonymous-Consumer')) !== 'true') return
      await kong.service.request.clear_header('X-Consumer-Id')
      await kong.service.request.clear_header('X-Consumer-Username')
      if (!this.graphApiClient) {
        await this.buildGraghapiClient()
      }
      const SIGNED_KEY = process.env.SIGNED_KEY
      const token = parseBearerToken({ headers: { authorization: headerToken } })
      if (!token) {
        return kong.response.exit(401, {
          error_description: 'The access token is missing',
          error: 'invalid_request'
        })
      }

      const payload = jwt.decode(token)
      if (!payload) {
        kong.log.warn('invalid JWT format')
        return kong.response.exit(401, {
          error_description: 'The access token is invalid',
          error: 'invalid_request'
        })
      }

      const signedKey = SIGNED_KEY ? { signingKey: SIGNED_KEY } : await this.getSignedKey(token, payload.extension_tenantId)
      const { err, decoded } = await verifyJWT(token, signedKey.signingKey, { audience: this.config.upstream_client_id })
      if (err) {
        if (err.name === 'TokenExpiredError') {
          return kong.response.exit(401, {
            error_description: 'The access token is expired',
            error: 'invalid_request'
          })
        } else {
          kong.log.warn(JSON.stringify(err))
          kong.log.warn(JSON.stringify(err.message))
          kong.log.warn(JSON.stringify(err.stack))
          return kong.response.exit(401, {
            error_description: 'The access token is invalid',
            error: 'invalid_request'
          })
        }
      }

      if (decoded.iss.includes('login.microsoftonline.com')) {
        const client = (await this.graphApiClient
          .api(`/applications?$filter=appId eq '${decoded.azp}'`)
          .get()).value[0]
        const data = { client, token: decoded }
        Object.keys(this.config.client_credentials.header_mapping).forEach(async key => {
          const { from, value, encode } = this.config.client_credentials.header_mapping[key]
          const headerValue = encode === 'url_encode' ? encodeURIComponent(data[from][value]) : data[from][value]
          if (key) { await kong.service.request.setHeader(key, headerValue) }
        })
      } else {
        const user = (await this.graphApiClient
          .api(`/users/${decoded.sub}`)
          .get()).value[0]
        const client = (await this.graphApiClient
          .api(`/applications?$filter=appId eq '${decoded.azp}'`)
          .get()).value[0]
        const data = { user, client, token: decoded }
        Object.keys(this.config.authorization_code.header_mapping).forEach(async key => {
          const { from, value, encode } = this.config.authorization_code.header_mapping[key]
          const headerValue = encode === 'url_encode' ? encodeURIComponent(data[from][value]) : data[from][value]
          if (key) { await kong.service.request.setHeader(key, headerValue) }
        })
      }
    } catch (e) {
      kong.log.err(JSON.stringify(e))
      kong.log.err(JSON.stringify(e.message))
      kong.log.err(JSON.stringify(e.stack))
      kong.response.exit(500, {
        error_description: 'Unknown_error',
        error: 'Unknown_error'
      })
    }
  }

  async getSignedKey (token, tenantId) {
    const client = tenantId ? this.authorizationCodeJwksClient : this.clientCredentialsJwksClient

    const signingKey = await getSigningKey(client, jwt.decode(token, { complete: true }).header.kid)
    return signingKey
  }
}

module.exports = {
  Plugin: OidcForAzureADB2CPlugin,
  Schema: [
    { upstream_client_id: { type: 'string', required: true } },
    {
      authorization_code: {
        type: 'record',
        fields: [{
          header_mapping: {
            type: 'map',
            required: false,
            keys: { type: 'string' },
            values: {
              type: 'record',
              fields: [
                { from: { type: 'string', one_of: ['token', 'user', 'client'] } },
                { value: { type: 'string' } },
                { encode: { type: 'string', one_of: ['none', 'url_encode'], default: 'none' } }
              ]
            }
          }
        }],
        default: {
          header_mapping: {
            'X-Authenticated-Client-Id': { from: 'token', value: 'azp' },
            'X-Authenticated-User-Id': { from: 'token', value: 'sub' }
          }
        }
      }
    },
    {
      client_credentials: {
        type: 'record',
        fields: [{
          header_mapping: {
            type: 'map',
            required: false,
            keys: { type: 'string' },
            values: {
              type: 'record',
              fields: [
                { from: { type: 'string', one_of: ['token', 'client'] } },
                { value: { type: 'string' } },
                { encode: { type: 'string', one_of: ['none', 'url_encode'], default: 'none' } }
              ]
            }
          }
        }],
        default: {
          header_mapping: {
            'X-Authenticated-Client-Id': { from: 'token', value: 'azp' }
          }
        }
      }
    }
  ],
  Version: '0.1.0',
  Priority: 999
}
