# AuthenticService #

This is the service component of [authentic](https://github.com/davidguttman/authentic). This will help decode tokens so that you can authenticate users within a microservice.

## Example ##

```js
var http = require('http')
var Authentic = require('authentic-service')

var auth = Authentic({
  server: 'https://auth.scalehaus.io'
})

http.createServer(function (req, res) {
  // Step 1: decrypt the token
  auth(req, res, function (err, authData) {
    if (err) return console.error(err)

    // Step 2: if we get an email and it's one we like, let them in!
    if (authData && authData.email.match(/@scalehaus\.io$/)) {
      res.writeHead(200)
      res.end('You\'re in!')

    // otherwise, keep them out!
    } else {
      res.writeHead(403)
      res.end('Nope.')
    }
  })
}).listen(1338)

console.log('Protected microservice listening on port', 1338)
```

## Installation ##

```
npm install --save authentic-service
```

## API ##

### Authentic(opts) ###

This is the main entry point. Accepts an options object and returns a function that can parse and decrypt tokens from http requests.

```js
var auth = Authentic({
  server: 'https://auth.scalehaus.io'
})

// auth is now a function that accepts req, res, and a callback
auth(req, res, function(err, authData) { ... })
```

#### options ####

`Authentic()` takes an options object as its first argument, one of them is required:

* `server`: the url of the `authentic-server`, e.g. `'http://auth.yourdomain.com'`

Optional:

* `prefix`: defaults to `'/auth'` if you set a custom prefix for your `authentic-server`, use that same prefix here
* `cacheDuration`: defaults to `3600000` (1 hour in milliseconds). To minimize latency and requests, this is how long `authentic-service` will cache the `authentic-server` public key. 

# License #

MIT
