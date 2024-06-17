const map = require('map-async')
const jsonist = require('jsonist')
const Corsify = require('corsify')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const AsyncCache = require('async-cache')

const errors = {
  TokenExpiredError: 401,
  JsonWebTokenError: 401,
  NotBeforeError: 401,
  RemoteExpiryError: 401
}

const cors = Corsify({
  'Access-Control-Allow-Headers': 'authorization, accept, content-type'
})

module.exports = function (opts) {
  const prefix = opts.prefix || '/auth'
  const pubKeyUrl = opts.server + prefix + '/public-key'
  const expiredUrl = opts.server + prefix + '/expired'
  const checkExpiredList = opts.checkExpiredList || false

  const cache = createCache({ pubKeyUrl, expiredUrl }, opts.cacheDuration)

  const ops = ['pubKey']
  if (checkExpiredList) ops.push('expired')

  function decode (token, cb) {
    map(ops, cache.get.bind(cache), function (err, [pubKey, expired]) {
      if (err) return cb(err)
      jwt.verify(
        token,
        pubKey,
        { algorithms: ['RS256'] },
        function (err, data) {
          if (err) return cb(err)
          if (!checkExpiredList) return cb(null, data)

          if (isTokenExpiredByRemote(expired, data)) {
            const error = new CustomError('jwt expired by remote')
            error.name = 'RemoteExpiryError'
            return cb(error)
          }

          cb(null, data)
        }
      )
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

function createCache (opts, cacheDuration) {
  const pubKeyUrl = opts.pubKeyUrl
  const expiredUrl = opts.expiredUrl

  return new AsyncCache({
    maxAge: cacheDuration || 1000 * 60 * 60,

    load: function (key, cb) {
      if (key === 'pubKey') {
        loadPublicKey(pubKeyUrl, cb)
      } else if (key === 'expired') {
        loadExpired(expiredUrl, cb)
      }
    }
  })
}

function loadPublicKey (url, cb) {
  jsonist.get(url, function (err, body) {
    if (err) return cb(err)

    const pubKey = ((body || {}).data || {}).publicKey
    if (!pubKey) return cb(new Error('Could not retrieve public key'))

    cb(null, pubKey)
  })
}

function loadExpired (url, cb) {
  jsonist.get(url, function (err, body) {
    if (err) return cb(err)
    cb(null, body)
  })
}

function hashEmail (email) {
  return crypto.createHash('sha256').update(email).digest('hex')
}

function isTokenExpiredByRemote (expired, data) {
  if (!expired) return false
  const emailHash = hashEmail(data.email)
  return expired[emailHash] > data.iat
}

class CustomError extends Error {
  constructor (message) {
    super(message)
    this.name = this.constructor.name
    Object.defineProperty(this, 'message', {
      value: message,
      enumerable: true // Make message enumerable
    })
  }
}
