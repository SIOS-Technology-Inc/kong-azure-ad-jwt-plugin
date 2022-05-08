const chai = require('chai')
const expect = chai.expect
const fs = require('fs')
const jwt = require('jsonwebtoken')
const axios = require('axios')
const axiosRetry = require('axios-retry')
const uuid = require('uuid')
const kong = require('../utils/kong')
const { httpbinService, httpbinRoute, oidcForAzureADPlugin, oidcForAzureADB2CPlugin } = require('../kong-setting')

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
const jwtSecretForAD = fs.readFileSync('./test/stub/azure-ad-jwks-api/private.pem')
const jwtSecretForADB2C = fs.readFileSync('./test/stub/azure-ad-b2c-jwks-api/private.pem')

const anonymousId = uuid.v4()
const oauthPluginConsumerId = uuid.v4()

const expiredTokenForAD = () => {
  const jwtPayloadForClientCredentials = {
    iss: 'https://login.microsoftonline.com/',
    aud: 'upstream_client_id',
    azp: 'clientId'
  }
  const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '-1s'
  }

  return 'Bearer ' + jwt.sign(jwtPayloadForClientCredentials, jwtSecretForAD, jwtOptions)
}

const expiredTokenForADB2C = () => {
  const jwtPayload = {
    iss: '',
    sub: 'userId',
    aud: 'upstream_client_id',
    azp: 'clientId'
  }
  const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '-1s'
  }
  return 'Bearer ' + jwt.sign(jwtPayload, jwtSecretForADB2C, jwtOptions)
}

const invalidAudToken = () => {
  const jwtPayload = {
    sub: 'userId',
    azp: 'clientId',
    aud: 'invalid'
  }
  const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '3m'
  }
  return 'Bearer ' + jwt.sign(jwtPayload, jwtSecretForADB2C, jwtOptions)
}

const credentialsToken = () => {
  const jwtPayloadForClientCredentials = {
    iss: 'https://login.microsoftonline.com/',
    aud: 'upstream_client_id',
    azp: 'clientId'
  }
  const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '3m'
  }

  return 'Bearer ' + jwt.sign(jwtPayloadForClientCredentials, jwtSecretForAD, jwtOptions)
}

const authorizationCodeTokenForAD = () => {
  const jwtPayloadForAuthorizationCode = {
    iss: 'https://login.microsoftonline.com/',
    sub: 'userId',
    aud: 'upstream_client_id',
    azp: 'clientId',
    name: 'name'
  }
  const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '3m'
  }

  return 'Bearer ' + jwt.sign(jwtPayloadForAuthorizationCode, jwtSecretForAD, jwtOptions)
}

const authorizationCodeTokenForADB2C = () => {
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

  return 'Bearer ' + jwt.sign(jwtPayloadForAuthorizationCode, jwtSecretForADB2C, jwtOptions)
}

const kongCredentialsToken = async () => {
  const client = axios.create({ baseURL: 'https://localhost:8443' })
  axiosRetry(client, {
    retries: 5,
    retryDelay: axiosRetry.exponentialDelay,
    retryCondition: (error) => error.response.status >= 300
  })
  return 'Bearer ' + (await client.post('https://localhost:8443/oauth2/token', {
    client_id: 'testClientId',
    client_secret: 'testClientSecret',
    grant_type: 'client_credentials'
  }, {
    headers: { Host: 'httpbin.org' }
  })).data.access_token
}

const validRequestsForOAuth2 = [
  {
    name: 'Valid token for oauth2 plugin request',
    token: kongCredentialsToken,
    expected: {
      status: 200,
      headers: {
        'X-Consumer-Id': oauthPluginConsumerId,
        'X-Consumer-Username': 'testUsername',
        'X-Authenticated-Client-Id': undefined,
        'X-Authenticated-Client-Name': undefined
      }
    }
  }
]

const validRequestsForAD = [
  {
    name: 'Valid token request',
    token: credentialsToken,
    expected: {
      status: 200,
      headers: {
        'X-Authenticated-Client-Id': 'clientId',
        'X-Authenticated-Client-Name': 'clientName',
        'X-Consumer-Id': undefined,
        'X-Consumer-Username': undefined,
        Authorization: undefined
      }
    }
  },
  {
    name: 'Valid token request',
    token: authorizationCodeTokenForAD,
    expected: {
      status: 200,
      headers: {
        'X-Authenticated-Client-Id': 'clientId',
        'X-Authenticated-Client-Name': 'clientName',
        'X-Authenticated-User-Name': 'userName',
        'X-Consumer-Id': undefined,
        'X-Consumer-Username': undefined,
        Authorization: undefined
      }
    }
  }
]

const validRequestsForADB2C = [
  {
    name: 'Valid token request',
    token: authorizationCodeTokenForADB2C,
    expected: {
      status: 200,
      headers: {
        'X-Authenticated-Client-Id': 'clientId',
        'X-Authenticated-Client-Name': 'clientName',
        'X-Authenticated-User-Id': 'userId',
        'X-Authenticated-User-Name': 'userName',
        'X-Consumer-Id': undefined,
        'X-Consumer-Username': undefined,
        Authorization: undefined
      }
    }
  }
]

const invalidRequestsForAD = [
  {
    name: 'No token request',
    token: undefined,
    expected: {
      status: 401,
      body: {
        error: 'invalid_request',
        error_description: 'The access token is missing'
      }
    }
  },
  {
    name: 'Expired token request',
    token: expiredTokenForAD,
    expected: {
      status: 401,
      body: {
        error: 'invalid_request',
        error_description: 'The access token is expired'
      }
    }
  },
  {
    name: 'Invalid Aud token request',
    token: invalidAudToken,
    expected: {
      status: 401,
      body: {
        error: 'invalid_request',
        error_description: 'The access token is invalid'
      }
    }
  },
  {
    name: 'Invalid token request',
    token: () => 'Bearer invalidToken',
    expected: {
      status: 401,
      body: {
        error: 'invalid_request',
        error_description: 'The access token is invalid'
      }
    }
  }
]

const invalidRequestsForADB2C = [
  {
    name: 'No token request',
    token: undefined,
    expected: {
      status: 401,
      body: {
        error: 'invalid_request',
        error_description: 'The access token is missing'
      }
    }
  },
  {
    name: 'Expired token request',
    token: expiredTokenForADB2C,
    expected: {
      status: 401,
      body: {
        error: 'invalid_request',
        error_description: 'The access token is expired'
      }
    }
  },
  {
    name: 'Invalid Aud token request',
    token: invalidAudToken,
    expected: {
      status: 401,
      body: {
        error: 'invalid_request',
        error_description: 'The access token is invalid'
      }
    }
  },
  {
    name: 'Invalid token request',
    token: () => 'Bearer invalidToken',
    expected: {
      status: 401,
      body: {
        error: 'invalid_request',
        error_description: 'The access token is invalid'
      }
    }
  }
]

const AzureADConfig = {
  services: [
    {
      ...httpbinService,
      routes: [
        {
          ...httpbinRoute,
          plugins: [oidcForAzureADPlugin]
        }
      ]
    }
  ]
}

const AzureADAndWithOAuth2Config = {
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
              ...oidcForAzureADPlugin,
              config: {
                ...oidcForAzureADPlugin.config,
                use_kong_auth: true
              }
            }
          ]
        }
      ]
    }
  ]
}

const AzureADB2CConfig = {
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
}

const AzureADB2CWithOAuth2Config = {
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
}

const AzureADAndAzureADB2CConfig = {
  services: [
    {
      ...httpbinService,
      routes: [
        {
          ...httpbinRoute,
          plugins: [
            {
              ...oidcForAzureADPlugin,
              config: {
                ...oidcForAzureADPlugin.config,
                permit_anonymous: true
              }
            },
            oidcForAzureADB2CPlugin
          ]
        }
      ]
    }
  ]
}

const AzureADAndAzureADB2CWithOAuth2Config = {
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
              ...oidcForAzureADPlugin,
              config: {
                ...oidcForAzureADPlugin.config,
                permit_anonymous: true,
                use_kong_auth: true
              }
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
}

describe('Function test', () => {
  const tests = [
    {
      name: 'When using oidc-for-azure-ad',
      config: AzureADConfig,
      requests: [
        ...invalidRequestsForAD,
        ...validRequestsForAD
      ]
    },
    {
      name: 'When using oidc-for-azure-ad and oauth2',
      config: AzureADAndWithOAuth2Config,
      requests: [
        ...invalidRequestsForAD,
        ...validRequestsForAD,
        ...validRequestsForOAuth2
      ]
    },
    {
      name: 'When using oidc-for-azure-ad-b2c',
      config: AzureADB2CConfig,
      requests: [
        ...invalidRequestsForADB2C,
        ...validRequestsForADB2C
      ]
    },
    {
      name: 'When using oidc-for-azure-ad-b2c and oauth2',
      config: AzureADB2CWithOAuth2Config,
      requests: [
        ...invalidRequestsForADB2C,
        ...validRequestsForADB2C,
        ...validRequestsForOAuth2
      ]
    },
    {
      name: 'When using oidc-for-azure-ad and oidc-for-azure-ad-b2c',
      config: AzureADAndAzureADB2CConfig,
      requests: [
        ...invalidRequestsForAD,
        ...validRequestsForAD,
        ...invalidRequestsForADB2C,
        ...validRequestsForADB2C
      ]
    },
    {
      name: 'When using oidc-for-azure-ad, oidc-for-azure-ad-b2c and oauth2',
      config: AzureADAndAzureADB2CWithOAuth2Config,
      requests: [
        ...invalidRequestsForAD,
        ...validRequestsForAD,
        ...invalidRequestsForADB2C,
        ...validRequestsForADB2C,
        ...validRequestsForOAuth2
      ]
    }
  ]

  tests.forEach(({ name, config, requests }) => {
    describe(name, () => {
      before('setting kong', async () => {
        await kong.reset()
        await kong.sync(config)
      })
      requests.forEach(({ name, token, expected }) => {
        describe(name, () => {
          let res
          before(async () => {
            const headers = { Host: 'httpbin.org' }
            if (token) {
              headers.Authorization = await token()
            }
            res = await axios.get('http://localhost:8000/get', {
              headers,
              validateStatus: (status) => status < 500
            })
          })
          if (expected.status) {
            it(`returns ${expected.status} as status`, () => {
              expect(res.status).to.equal(expected.status, JSON.stringify(res.data))
            })
          }
          if (expected.body) {
            Object.keys(expected.body).forEach((key) => {
              it(`returns '${expected.body[key]}' at '${key}' property in body`, () => {
                expect(res.data[key]).to.equal(expected.body[key])
              })
            })
          }
          if (expected.headers) {
            Object.keys(expected.headers).forEach((key) => {
              if (expected.headers[key]) {
                it(`gives upstream '${expected.headers[key]}' at '${key}' header`, () => {
                  expect(res.data.headers).to.have.property(key, expected.headers[key])
                })
              } else {
                it(`doesn't give upstream '${key}' header`, () => {
                  expect(res.data.headers).not.to.have.property(key)
                })
              }
            })
          }
        })
      })
    })
  })
})
