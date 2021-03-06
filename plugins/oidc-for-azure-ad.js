const { OidcForAzure } = require('./lib/oidc-for-azure')
const { JWK } = require('./lib/jwt-helper')

class OidcForAzureADPlugin extends OidcForAzure {
  jwk () {
    const baseURL = process.env.AZURE_AD_JWKS_URL || 'https://login.microsoftonline.com'
    const path = '/common/discovery/keys'
    return new JWK(baseURL + path)
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
          'X-Authenticated-User-Id': { from: 'user', value: 'id' }
        }
      }
    },
    { permit_anonymous: { type: 'boolean', default: false } }
  ],
  Version: '0.1.0',
  Priority: 999
}
