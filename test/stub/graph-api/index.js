const express = require('express')
const app = express()

const port = process.env.PORT || 8080

app.use((req, res, next) => {
  console.log(JSON.stringify({
    method: req.method,
    path: req.path,
    query: req.query
  }))
  next()
})

app.post(/.*\/token/, (req, res) => {
  res.status(200).send({
    token_type: 'Bearer',
    expires_in: 3599,
    access_token: 'token'
  })
})

app.get('/v1.0/applications', (req, res) => {
  res.status(200).send({
    value: [{
      displayName: 'clientName'
    }]
  })
})

app.get('/v1.0/users', (req, res) => {
  res.status(200).send({
    value: [{
      displayName: 'userName'
    }]
  })
})

app.listen(port, () => {
  console.log(`Start Graph API Stub Server on ${port}`)
})
