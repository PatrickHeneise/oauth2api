var
  debug = require('debug')('oauth:index'),
  passport = require('passport'),
  LocalStrategy = require('passport-local').Strategy,
  TwitterStrategy = require('passport-twitter').Strategy,
  BearerStrategy = require('passport-http-bearer').Strategy,
  redis = require('redis'),
  store = redis.createClient(),
  oauth2 = require('./oauth2'),
  oauth2orize = require('oauth2orize'),
  server = oauth2orize.createServer(),
  login = require('connect-ensure-login');

passport.serializeUser(function (user, done) {
  debug('serialise user: %s', user.id);

  delete user.password;
  delete user.salt;

  store.hmset('user-' + user.id, user);
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  debug('de-serialise user: %s', id);

  store.hgetall('user-' + id, function (error, user) {
    if (error) {
      done(error);
    } else {
      done(null, user);
    }
  });
});

server.serializeClient(function (client, done) {
  debug('serialise client: %s', client.id);

  store.hmset('client-' + client.id, client);
  return done(null, client.id);
});

server.deserializeClient(function (id, done) {
  store.hgetall('client-' + id, function (error, client) {
    if (error) {
      done(error);
    } else {
      done(null, client);
    }
  });
});

passport.use(new LocalStrategy(
  function (email, password, done) {
    debug('Login attempt by: %s', email);

    process.nextTick(function () {
      // find a user by email
    });
  })
);

passport.use(new BearerStrategy({}, function (token, done) {
  debug('Bearer login token: %s', token);

  process.nextTick(function () {
    // Find the user by token.  If there is no user with the given token, set
    // the user to `false` to indicate failure.  Otherwise, return the
    // authenticated `user`.  Note that in a production-ready application, one
    // would want to validate the token for authenticity.
  });
}));

exports.configure = function (app) {
  app.all('*', function (req, res, next) {
    next();
  });

  app.get('/login', function (req, res) {
    res.send('<form action="/login" method="post"><div><label>Username:</label><input type="text"' +
    ' name="username"/><br/></div><div><label>Password:</label><input type="password" name=' +
    '"password"/></div><div><input type="submit" value="Submit"/></div></form><p><small>Hint - ' +
    'bob:secret</small></p><p><small>Hint - joe:password</small></p>');
  });
  app.post('/login', passport.authenticate('local', {
    successReturnToOrRedirect: '/tiles',
    failureRedirect: '/login'
  }));

  app.get('/oauth/authorize', oauth2.authorization);
  app.post('/oauth/authorize/decision', oauth2.decision);
  app.post('/oauth/token', oauth2.token);

  app.get('/', function (req, res) {
		// nothing
  });
};
