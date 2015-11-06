var fs = require('fs')
var http = require('http')
var tape = require('tape')
var servertest = require('servertest')
var jwt = require('jsonwebtoken')

var publicKey = fs.readFileSync(__dirname + '/rsa-public.pem', 'utf-8')
var privateKey = fs.readFileSync(__dirname + '/rsa-private.pem', 'utf-8')

var Authentic = require('../')

var server = null
var auth = null

var payload = {email: 'chet@scalehaus.io', expiresIn: '30d'}
var token = jwt.sign(payload, privateKey, {algorithm: 'RS256'})

tape('init', function (t) {
  server = http.createServer(function (req, res) {
    if (req.url !== '/auth/public-key') return
    res.end(JSON.stringify({
      "success": true,
      "data": { "publicKey": publicKey }
    }))
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
  var opts = {method: 'GET'}
  servertest(createService(auth), '/', opts, function (err, res) {
    t.ifError(err, 'should not error')
    var data = JSON.parse(res.body)
    t.equal(data, null, 'should not have authData')
    t.end()
  })
})

tape('should handle auth token', function (t) {
  var opts = {method: 'GET', headers: {
    Authorization: 'Bearer ' + token
  }}

  servertest(createService(auth), '/', opts, function (err, res) {
    t.ifError(err, 'should not error')
    var data = JSON.parse(res.body)

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
      if (err) return console.error(err)
      res.writeHead(200, {'Content-Type': 'application/json'})
      res.end(JSON.stringify(authData || null))
    })
  })
}
