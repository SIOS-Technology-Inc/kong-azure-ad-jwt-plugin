require('isomorphic-fetch')
const jwksClient = require('jwks-rsa')
const jwt = require('jsonwebtoken')
const parseBearerToken = require('parse-bearer-token').default
const { GraphApiHelper } = require('./lib/graph-api-helper')

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
    this.graphApiHelper = new GraphApiHelper(
      this.config.kong_client_id,
      this.config.kong_client_secret,
      this.config.azure_tenant,
      {
        graphApiLoginUrl: process.env.GRAPH_API_LOGIN_URL,
        graphApiBaseUrl: process.env.GRAPH_API_URL
      }
    )
    this.authorizationCodeJwksClient = jwksClient({
      jwksUri: config.authorization_code.jwks_url,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 600000 // 10min
    })
    this.clientCredentialsJwksClient = jwksClient({
      jwksUri: config.client_credentials.jwks_url,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 600000 // 10min
    })
  }

  async access (kong) {
    try {
      if (this.config.use_kong_auth && (await kong.request.get_header('X-Anonymous-Consumer')) !== 'true') return
      const headerToken = await kong.request.getHeader('Authorization')
      await kong.service.request.clear_header('Authorization')
      await kong.service.request.clear_header('X-Consumer-Id')
      await kong.service.request.clear_header('X-Consumer-Username')
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
        const client = await this.graphApiHelper.findClient(decoded.azp)
        const data = { client, token: decoded }
        Object.keys(this.config.client_credentials.header_mapping).forEach(async key => {
          const { from, value, encode } = this.config.client_credentials.header_mapping[key]
          const headerValue = encode === 'url_encode' ? encodeURIComponent(data[from][value]) : data[from][value]
          if (key) { await kong.service.request.setHeader(key, headerValue) }
        })
      } else {
        const user = await this.graphApiHelper.findUser(decoded.sub)
        const client = await this.graphApiHelper.findClient(decoded.azp)
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
    { kong_client_id: { type: 'string', required: true } },
    { kong_client_secret: { type: 'string', required: true } },
    { azure_tenant: { type: 'string', required: true } },
    { use_kong_auth: { type: 'boolean', default: false } },
    {
      authorization_code: {
        type: 'record',
        required: true,
        fields: [
          { jwks_url: { type: 'string', required: true } },
          {
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
              },
              default: {
                'X-Authenticated-Client-Id': { from: 'token', value: 'azp' },
                'X-Authenticated-User-Id': { from: 'token', value: 'sub' }
              }
            }
          }
        ]
      }
    },
    {
      client_credentials: {
        type: 'record',
        fields: [
          { jwks_url: { type: 'string', default: 'https://login.microsoftonline.com/common/discovery/keys' } },
          {
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
          }
        ],
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
