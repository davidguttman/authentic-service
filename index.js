const jsonist = require('jsonist')
const Corsify = require('corsify')
const jwt = require('jsonwebtoken')
const AsyncCache = require('async-cache')

const errors = {
  TokenExpiredError: 401,
  JsonWebTokenError: 401,
  NotBeforeError: 401
}

const cors = Corsify({
  'Access-Control-Allow-Headers': 'authorization, accept, content-type'
})

module.exports = function (opts) {
  const prefix = opts.prefix || '/auth'
  const pubKeyUrl = opts.server + prefix + '/public-key'
  const cache = createCache(pubKeyUrl, opts.cacheDuration)

  function decode (token, cb) {
    cache.get('pubKey', function (err, pubKey) {
      if (err) return cb(err)
      jwt.verify(token, pubKey, { algorithms: ['RS256'] }, cb)
    })
  }

  function parseRequest (req, res, cb) {
    cors(function (req, res) {
      const authHeader = req.headers.authorization
      if (!authHeader) return setImmediate(cb)
      const token = authHeader.slice(7)
      decode(token, function (err, authData) {
        if (err) err.statusCode = errors[err.name] || 500
        return cb(err, authData)
      })
    })(req, res)
  }

  return parseRequest
}

function createCache (pubKeyUrl, cacheDuration) {
  return new AsyncCache({
    maxAge: cacheDuration || 1000 * 60 * 60,

    load: function (key, cb) {
      jsonist.get(pubKeyUrl, function (err, body) {
        if (err) return cb(err)

        const pubKey = ((body || {}).data || {}).publicKey
        if (!pubKey) return cb(new Error('Could not retrieve public key'))

        cb(null, pubKey)
      })
    }
  })
}
