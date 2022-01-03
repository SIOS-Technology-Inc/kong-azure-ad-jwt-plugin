const axios = require('axios')
const graph = require('@microsoft/microsoft-graph-client')

class GraphApiHelper {
  constructor (clientId, clientSecret, azureTenant, options = {}) {
    options.graphApiLoginUrl = options.graphApiLoginUrl || 'https://login.microsoftonline.com'
    options.graphApiBaseUrl = options.graphApiBaseUrl || 'https://graph.microsoft.com'
    const getAccessTokenFunc = async () => {
      const params = new URLSearchParams()
      params.append('client_id', clientId)
      params.append('client_secret', clientSecret)
      params.append('scope', 'https://graph.microsoft.com/.default')
      params.append('grant_type', 'client_credentials')
      return (await axios.post(`${options.graphApiLoginUrl}/${azureTenant}/oauth2/v2.0/token`, params)).data.access_token
    }

    // When the access token expires, it will be automatically reacquired.
    this.graphApiClient = graph.Client.initWithMiddleware({
      authProvider: {
        getAccessToken: getAccessTokenFunc
      }
    })
    this.graphApiClient.config.baseUrl = options.graphApiBaseUrl
  }

  async findClient (clientId) {
    return (await this.graphApiClient
      .api(`/applications?$filter=appId eq '${clientId}'`)
      .get()).value[0]
  }

  async findUser (userId) {
    return (await this.graphApiClient
      .api(`/users/${userId}`)
      .get()).value[0]
  }
}

module.exports = { GraphApiHelper }
