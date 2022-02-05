const parseBearerToken = require('parse-bearer-token').default
const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')

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

class JWK {
  constructor (jwksUrl) {
    this.client = jwksClient({
      jwksUri: jwksUrl,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 600000 // 10min
    })
  }

  async getSignedKey (jwt) {
    const signingKey = await getSigningKey(this.client, jwt.header().kid)
    return signingKey
  }

  async validate (jwt, options) {
    const signedKey = options.signedKey || (await getSigningKey(this.client, jwt.header().kid)).signingKey
    return verifyJWT(jwt.token, signedKey, options)
  }
}

class JWT {
  constructor (token) {
    this.token = token
  }

  static fromBearer (bearer) {
    const token = parseBearerToken({ headers: { authorization: bearer } })
    return token ? new JWT(token) : undefined
  }

  payload () {
    return jwt.decode(this.token)
  }

  header () {
    return jwt.decode(this.token, { complete: true }).header
  }
}

module.exports = { JWK, JWT }
