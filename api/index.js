var
  debug = require('debug')('oauth:index'),
  passport = require('passport'),
  LocalStrategy = require('passport-local').Strategy,
  TwitterStrategy = require('passport-twitter').Strategy,
  BearerStrategy = require('passport-http-bearer').Strategy,
  ExampleStrategy = require('../passport-example').Strategy,
  redis = require('redis'),
  store = redis.createClient(),
  oauth2 = require('./oauth2'),
  login = require('connect-ensure-login');

passport.serializeUser(function (user, done) {
  debug('serialise user: %s', user.id);

  delete user.password;
  delete user.salt;

  store.hmset('session-user-' + user.id, user);
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  debug('de-serialise user: %s', id);

  store.hgetall('session-user-' + id, function (error, user) {
    if (error) {
      done(error);
    } else {
      done(null, user);
    }
  });
});

passport.use(new LocalStrategy({
  usernameField: 'email'
}, function (email, password, done) {
  debug('Login attempt by: %s', email);

  process.nextTick(function () {
    store.get('email-' + email, function (error, email) {
      store.hgetall('user-' + email, function (error, user) {
        if (user.password === password) {
          done(error, user);
        } else {
          done('wrong password');
        }
      });
    });
  });
}));

passport.use('exampleauth', new ExampleStrategy({
  authorizationURL: 'https://localhost:3000/oauth2/authorize',
  tokenURL: 'https://localhost:3000/oauth2/token',
  clientID: 'coolclient',
  clientSecret: 'helloworld',
  callbackURL: 'https://localhost:3000/oauth2/callback'
}, function (accessToken, refreshToken, profile, done) {
  store.hgetall('access-token-' + accessToken, function (error, token) {
    if (error) {
      done(error);
    } else {
      store.hgetall('user-' + token.user, function (error, user) {
        done(null, user);
      });
    }
  });
}));

passport.use(new BearerStrategy(
  function (accessToken, done) {
    store.hgetall('access-token-' + accessToken, function (error, token) {
      if (error) {
        return done(error);
      }
      if (!token) {
        return done(null, false);
      }
      if (token.user) {
        store.hgetall('user-' + token.user, function (error, user) {
          done(null, user);
        });
      } else {
        //The request came from a client only since userID is null
        //therefore the client is passed back instead of a user
        store.hgetall('client-' + token.client, function (error, client) {
          if (error) {
            return done(error);
          }
          if (!client) {
            return done(null, false);
          }
          // to keep this example simple, restricted scopes are not implemented,
          // and this is just for illustrative purposes
          var info = {
            scope: '*'
          };
          done(null, client, info);
        });
      }
    });
  }
));

exports.configure = function (app) {
  app.get('/start', function (req, res) {
    res.send('<a href="http://localhost:3000/dialog/authorize?response_type=code&client_id=coolclient' +
      '&scope=somescope&redirect_uri=http://localhost:3000">authorize</a>');
  });

  // OAuth 2.0 Server routes
  app.get('/login', function (req, res) {
    res.send('<form action="/login" method="post"><div><label>email:</label><input type="text"' +
      ' name="email"/><br/></div><div><label>Password:</label><input type="password" name=' +
      '"password"/></div><div><input type="submit" value="Submit"/></div></form><p><small>Hint - ' +
      'anything</small></p>');
  });

  app.post('/login', passport.authenticate('local', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/login'
  }));

  app.get('/user', passport.authenticate('bearer', { session: false }), function (req, res) {
    // req.authInfo is set using the `info` argument supplied by
    // `BearerStrategy`.  It is typically used to indicate scope of the token,
    // and used in access control checks.  For illustrative purposes, this
    // example simply returns the scope in the response.
    res.json({
      id: req.user.id,
      first_name: req.user.first_name,
      last_name: req.user.last_name,
      scope: req.authInfo.scope
    });
  });

  app.get('/oauth2/authorize', oauth2.authorization);
  app.post('/oauth2/authorize/decision', oauth2.decision);
  app.post('/oauth2/token', oauth2.token);


  // OAuth2 consumer routes
  app.get('/oauth2/callback', passport.authenticate('exampleauth', {
    failureRedirect: '/error'
  }));
  app.get('/oauth2/callback', function (req, res) {
    console.log('req.session');
    console.log(req.session);
    console.log(req.user);

    res.send(200);
  });
};
