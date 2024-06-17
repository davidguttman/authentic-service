const fs = require('fs')
const http = require('http')
const jwt = require('jsonwebtoken')
const path = require('path')
const servertest = require('dg-servertest')
const tape = require('tape')

const publicKey = fs.readFileSync(
  path.join(__dirname, '/rsa-public.pem'),
  'utf-8'
)
const privateKey = fs.readFileSync(
  path.join(__dirname, '/rsa-private.pem'),
  'utf-8'
)

const Authentic = require('../')

let server = null
let auth = null

const payload = { email: 'chet@scalehaus.io', expiresIn: '30d' }
const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' })

tape('init', function (t) {
  server = http.createServer(function (req, res) {
    if (req.url !== '/auth/public-key') return
    res.end(
      JSON.stringify({
        success: true,
        data: { publicKey }
      })
    )
  })

  server.listen(0, function (err) {
    if (err) return console.error(err)
    auth = Authentic({
      server: 'http://localhost:' + this.address().port
    })
    t.end()
  })
})

tape('should handle anonymous request', function (t) {
  const opts = { method: 'GET' }
  servertest(createService(auth), '/', opts, function (err, res) {
    t.ifError(err, 'should not error')
    const data = JSON.parse(res.body)
    t.equal(data, null, 'should not have authData')
    t.end()
  })
})

tape('should handle bad jwt', function (t) {
  const opts = {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + 'not a jwt'
    }
  }
  servertest(createService(auth), '/', opts, function (err, res) {
    t.ifErr(err, 'should not error on bad token')

    const parsed = JSON.parse(res.body.toString())
    t.deepEqual(
      parsed,
      {
        message: 'jwt malformed',
        name: 'JsonWebTokenError',
        statusCode: 401
      },
      'should have correct error'
    )
    t.end()
  })
})

tape('should handle missing token error', function (t) {
  const opts = {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + ''
    }
  }
  servertest(createService(auth), '/', opts, function (err, res) {
    t.ifErr(err, 'should not error on bad token')

    const parsed = JSON.parse(res.body.toString())
    t.deepEqual(
      parsed,
      {
        message: 'jwt must be provided',
        name: 'JsonWebTokenError',
        statusCode: 401
      },
      'should have correct error'
    )
    t.end()
  })
})

tape("should handle 'TokenExpiredError'", function (t) {
  const payload = { email: 'chet@scalehaus.io' }
  const soonToExpireToken = jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    expiresIn: '1'
  })
  const opts = {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + soonToExpireToken
    }
  }
  const serviceInstance = createService(auth)
  setTimeout(function test () {
    servertest(serviceInstance, '/', opts, function (err, res) {
      t.ifErr(err, 'should not error on expired jwt')

      const parsed = JSON.parse(res.body.toString())
      t.equal(parsed.statusCode, 401, 'status code matches')
      t.equal(parsed.message, 'jwt expired', 'should have correct message')
      t.equal(parsed.name, 'TokenExpiredError', 'should have correct name')
      t.end()
    })
  }, 5)
})

tape("should handle 'NotBeforeError'", function (t) {
  const nbf = new Date().getTime() + 10000
  const payload = { email: 'chet@scalehaus.io', nbf }
  const soonToExpireToken = jwt.sign(payload, privateKey, {
    algorithm: 'RS256'
  })
  const opts = {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + soonToExpireToken
    }
  }
  const serviceInstance = createService(auth)
  setTimeout(function test () {
    servertest(serviceInstance, '/', opts, function (err, res) {
      t.ifErr(err, 'should not error on expired jwt')

      const parsed = JSON.parse(res.body.toString())
      t.equal(parsed.statusCode, 401, 'status code matches')
      t.equal(parsed.message, 'jwt not active', 'should have correct message')
      t.equal(parsed.name, 'NotBeforeError', 'should have correct name')
      t.end()
    })
  }, 5)
})

tape('should handle auth token', function (t) {
  const opts = {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + token
    }
  }

  servertest(createService(auth), '/', opts, function (err, res) {
    t.ifError(err, 'should not error')
    const data = JSON.parse(res.body)

    t.equal(data.email, 'chet@scalehaus.io', 'should have correct email')
    t.equal(data.expiresIn, '30d', 'should have correct expiresIn')
    t.ok(data.iat, 'chet@scalehaus.io', 'should have iat')

    t.end()
  })
})

tape('cleanup', function (t) {
  server.close()
  t.end()
})

function createService (auth) {
  return http.createServer(function (req, res) {
    auth(req, res, function (err, authData) {
      if (err) {
        err.stack = undefined
        res.writeHead(err.statusCode, { 'Content-Type': 'application/json' })
        return res.end(JSON.stringify(err))
      }
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(authData || null))
    })
  })
}
