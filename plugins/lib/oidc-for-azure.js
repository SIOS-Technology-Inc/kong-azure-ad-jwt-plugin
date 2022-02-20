require('isomorphic-fetch')
const { GraphApiHelper } = require('./graph-api-helper')
const { JWT } = require('./jwt-helper')

class OidcForAzure {
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
  }

  async access (kong) {
    try {
      if (this.config.use_kong_auth && (await kong.request.get_header('X-Anonymous-Consumer')) !== 'true') return
      if ((await kong.request.get_header('X-Anonymous')) === 'false') return
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
      const { err, decoded } = await this.jwk(payload).validate(token, {
        audience: this.config.upstream_client_id,
        signedKey: SIGNED_KEY
      })
      if (err) {
        if (this.config.permit_anonymous) {
          await kong.service.request.setHeader('X-Anonymous', 'true')
          return
        }
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

      const user = decoded.name ? await this.graphApiHelper.findUser(decoded.oid) : undefined
      const client = await this.graphApiHelper.findClient(decoded.azp)
      const data = { user, client, token: decoded }
      Object.keys(this.config.header_mapping).forEach(async key => {
        const { from, value, encode } = this.config.header_mapping[key]
        if (!(data[from] || {})[value]) return
        const headerValue = encode === 'url_encode' ? encodeURIComponent(data[from][value]) : data[from][value]
        if (key) { await kong.service.request.setHeader(key, headerValue) }
      })
      await kong.service.request.setHeader('X-Anonymous', 'false')
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

module.exports = { OidcForAzure }
