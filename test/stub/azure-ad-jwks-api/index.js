const express = require('express')
const fs = require('fs')
const rsaPemToJwk = require('rsa-pem-to-jwk')
const app = express()

const port = process.env.PORT || 8080

const pem = fs.readFileSync('private.pem')
const jwk = rsaPemToJwk(pem, { use: 'sig' }, 'public')

app.use((req, res, next) => {
  console.log(JSON.stringify({
    method: req.method,
    path: req.path,
    query: req.query
  }))
  next()
})

app.get('/common/discovery/keys', (req, res) => {
  res.status(200).send({
    keys: [jwk]
  })
})

app.listen(port, () => {
  console.log(`Start Graph API Stub Server on ${port}`)
})
