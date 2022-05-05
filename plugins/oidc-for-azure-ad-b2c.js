const { OidcForAzure } = require('./lib/oidc-for-azure')
const { JWK } = require('./lib/jwt-helper')

class OidcForAzureADB2CPlugin extends OidcForAzure {
  jwk (token) {
    const baseURL = process.env.AZURE_AD_B2C_JWKS_URL || `https://${this.config.azure_tenant}.b2clogin.com`
    const path = `/${this.config.azure_tenant}.onmicrosoft.com/${token.tfp}/discovery/v2.0/keys`
    return new JWK(baseURL + path)
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
    },
    { permit_anonymous: { type: 'boolean', default: false } }
  ],
  Version: '0.1.0',
  Priority: 998
}
