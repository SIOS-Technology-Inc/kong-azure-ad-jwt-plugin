const httpbinService = {
  host: 'kong-upstream-server',
  name: 'httpbin'
}

const httpbinRoute = {
  hosts: ['httpbin.org'],
  name: 'httpbin-route',
  protocols: ['http'],
  strip_path: false
}

const oidcForAzureADPlugin = {
  name: 'oidc-for-azure-ad',
  config: {
    upstream_client_id: 'upstream_client_id',
    kong_client_id: 'client_id',
    kong_client_secret: 'client_secret',
    azure_tenant: 'test.example.com',
    header_mapping: {
      'X-Authenticated-Client-Id': { from: 'token', value: 'azp' },
      'X-Authenticated-Client-Name': { from: 'client', value: 'displayName', encode: 'url_encode' },
      'X-Authenticated-User-Name': { from: 'user', value: 'displayName', encode: 'url_encode' }
    }
  }
}

const oidcForAzureADB2CPlugin = {
  name: 'oidc-for-azure-ad-b2c',
  config: {
    upstream_client_id: 'upstream_client_id',
    kong_client_id: 'client_id',
    kong_client_secret: 'client_secret',
    azure_tenant: 'test.example.com',
    header_mapping: {
      'X-Authenticated-Client-Id': { from: 'token', value: 'azp' },
      'X-Authenticated-Client-Name': { from: 'client', value: 'displayName', encode: 'url_encode' },
      'X-Authenticated-User-Id': { from: 'token', value: 'sub' },
      'X-Authenticated-User-Name': { from: 'user', value: 'displayName', encode: 'url_encode' }
    }
  }
}

module.exports = {
  httpbinService,
  httpbinRoute,
  oidcForAzureADPlugin,
  oidcForAzureADB2CPlugin
}
