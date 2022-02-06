require('isomorphic-fetch')
const { GraphApiHelper } = require('./lib/graph-api-helper')
const { JWK, JWT } = require('./lib/jwt-helper')

class OidcForAzureADPlugin {
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
    this.clientCredentialsJwk = new JWK(config.jwks_url)
  }

  async access (kong) {
    try {
      if (this.config.use_kong_auth && (await kong.request.get_header('X-Anonymous-Consumer')) !== 'true') return
      const headerToken = await kong.request.getHeader('Authorization')
      await kong.service.request.clear_header('Authorization')
      await kong.service.request.clear_header('X-Consumer-Id')
      await kong.service.request.clear_header('X-Consumer-Username')
      const SIGNED_KEY = process.env.SIGNED_KEY
      const token = JWT.fromBearer(headerToken)
      if (!token) {
        return kong.response.exit(401, {
          error_description: 'The access token is missing',
          error: 'invalid_request'
        })
      }

      const payload = token.payload()
      if (!payload) {
        kong.log.warn('invalid JWT format')
        return kong.response.exit(401, {
          error_description: 'The access token is invalid',
          error: 'invalid_request'
        })
      }
      const { err, decoded } = await this.clientCredentialsJwk.validate(token, {
        audience: this.config.upstream_client_id,
        signedKey: SIGNED_KEY
      })

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

      const client = await this.graphApiHelper.findClient(decoded.azp)
      const data = { client, token: decoded }
      Object.keys(this.config.header_mapping).forEach(async key => {
        const { from, value, encode } = this.config.header_mapping[key]
        const headerValue = encode === 'url_encode' ? encodeURIComponent(data[from][value]) : data[from][value]
        if (key) { await kong.service.request.setHeader(key, headerValue) }
      })
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
}

module.exports = {
  Plugin: OidcForAzureADPlugin,
  Schema: [
    { upstream_client_id: { type: 'string', required: true } },
    { kong_client_id: { type: 'string', required: true } },
    { kong_client_secret: { type: 'string', required: true } },
    { azure_tenant: { type: 'string', required: true } },
    { use_kong_auth: { type: 'boolean', default: false } },
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
        },
        default: { 'X-Authenticated-Client-Id': { from: 'token', value: 'azp' } }
      }
    }
  ],
  Version: '0.1.0',
  Priority: 999
}
