/**
 * Module dependencies.
 */
var
  debug = require('debug')('oauth2:lib'),
  oauth2orize = require('oauth2orize'),
  passport = require('passport'),
  BasicStrategy = require('passport-http').BasicStrategy,
  ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy,
  redis = require('redis'),
  store = redis.createClient(),
  login = require('connect-ensure-login'),
  idgen = require('idgen');

passport.use(new ClientPasswordStrategy(
  function (clientId, clientSecret, done) {
    process.nextTick(function () {
      store.hgetall('client-' + clientId, function (error, client) {
        if (error) {
          return done(error);
        }
        if (!client) {
          return done(null, false);
        }
        if (client.client_secret !== clientSecret) {
          return done(null, false);
        }
        return done(null, client);
      });
    });
  }
));

passport.use(new BasicStrategy({
    usernameField: 'clientId',
    passwordField: 'clientSecret'
  },
  function (clientId, clientSecret, done) {
    process.nextTick(function () {
      store.hgetall('client-' + clientId, function (error, client) {
        if (error) {
          return done(error);
        }
        if (!client) {
          return done(null, false);
        }
        if (client.client_secret !== clientSecret) {
          return done(null, false);
        }
        return done(null, client);
      });
    });
  }
));

// create OAuth 2.0 server
var server = oauth2orize.createServer();

// Register serialialization and deserialization functions.
//
// When a client redirects a user to user authorization endpoint, an
// authorization transaction is initiated.  To complete the transaction, the
// user must authenticate and approve the authorization request.  Because this
// may involve multiple HTTP request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session.  Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.

server.serializeClient(function (client, done) {
  debug('serialise client: %s', client.client_id);

  store.hmset('session-client-' + client.client_id, client);
  return done(null, client.client_id);
});

server.deserializeClient(function (id, done) {
  debug('de-serialise client: %s', id);

  store.hgetall('session-client-' + id, function (error, client) {
    if (error) {
      done(error);
    } else {
      done(null, client);
    }
  });
});

// Register supported grant types.
//
// OAuth 2.0 specifies a framework that allows users to grant client
// applications limited access to their protected resources.  It does this
// through a process of the user granting access, and the client exchanging
// the grant for an access token.

// Grant authorization codes.  The callback takes the `client` requesting
// authorization, the `redirectURI` (which is used as a verifier in the
// subsequent exchange), the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a code, which is bound to these
// values, and will be exchanged for an access token.

server.grant(oauth2orize.grant.code(function (client, redirectURI, user, ares, done) {
  var code = idgen(64);

  store.hmset('grant-' + code, {
    client: client.client_id,
    redirect_uri: redirectURI,
    user: user.id
  }, function (error) {
    if (error) {
      return done(error);
    }
    done(null, code);
  });
}));

// Grant implicit authorization.  The callback takes the `client` requesting
// authorization, the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a token, which is bound to these
// values.

server.grant(oauth2orize.grant.token(function (client, user, ares, done) {
  var token = idgen(256);

  store.hmset('authorization-code-' + token, {
    user: user.id,
    ares: ares,
    client: client.client_id
  }, function (error) {
    if (error) {
      return done(error);
    }
    done(null, token);
  });
}));


// Exchange authorization codes for access tokens.  The callback accepts the
// `client`, which is exchanging `code` and any `redirectURI` from the
// authorization request for verification.  If these values are validated, the
// application issues an access token on behalf of the user who authorized the
// code.

server.exchange(oauth2orize.exchange.code(function (client, code, redirectURI, done) {
  debug('token exchange', client.client_id, code);

  store.hgetall('grant-' + code, function (error, authCode) {
    var token = idgen(128);

    if (error) {
      return done(error);
    }
    if (client.client_id !== authCode.client) {
      return done(null, false);
    }
    if (redirectURI !== authCode.redirect_uri) {
      return done(null, false);
    }

    store.hmset('access-token-' + token, {
      user: authCode.user,
      client: authCode.client
    }, function (error) {
      if (error) {
        return done(error);
      }
      done(null, token);
    });
  });
}));

// Exchange user id and password for access tokens.  The callback accepts the
// `client`, which is exchanging the user's name and password from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the user who authorized the code.

server.exchange(oauth2orize.exchange.password(function (client, username, password, scope, done) {
  debug('user id password exchange', client, username);

  //Validate the client
  store.hgetall('client-' + client.clientId, function (error, localClient) {
    if (error) {
      return done(error);
    }
    if (localClient === null) {
      return done(null, false);
    }
    if (localClient.client_secret !== client.clientSecret) {
      return done(null, false);
    }
    //Validate the user
    store.hgetall('user-' + username, function (error, user) {
      if (error) {
        return done(error);
      }
      if (user === null) {
        return done(null, false);
      }
      if (password !== user.password) {
        return done(null, false);
      }
      //Everything validated, return the token
      var token = idgen(256);
      store.hmset('access-token-' + token, {
        user: user.id,
        client: client.clientId
      }, function (error) {
        if (error) {
          return done(error);
        }
        done(null, token);
      });
    });
  });
}));

// Exchange the client id and password/secret for an access token.  The callback accepts the
// `client`, which is exchanging the client's id and password/secret from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the client who authorized the code.

server.exchange(oauth2orize.exchange.clientCredentials(function (client, scope, done) {
  debug('exchange client id/secret for access token', client);

  //Validate the client
  store.hgetall('client-' + client.clientId, function (error, localClient) {
    if (error) {
      return done(error);
    }
    if (localClient === null) {
      return done(null, false);
    }
    if (localClient.client_secret !== client.clientSecret) {
      return done(null, false);
    }
    var token = idgen(256);
    //Pass in a null for user id since there is no user with this grant type
    store.hmset('access-token-' + token, {
      client: client.clientId
    }, function (error) {
      if (error) {
        return done(error);
      }
      done(null, token);
    });
  });
}));

// user authorization endpoint
//
// `authorization` middleware accepts a `validate` callback which is
// responsible for validating the client making the authorization request.  In
// doing so, is recommended that the `redirectURI` be checked against a
// registered value, although security requirements may vary accross
// implementations.  Once validated, the `done` callback must be invoked with
// a `client` instance, as well as the `redirectURI` to which the user will be
// redirected after an authorization decision is obtained.
//
// This middleware simply initializes a new authorization transaction.  It is
// the application's responsibility to authenticate the user and render a dialog
// to obtain their approval (displaying details about the client requesting
// authorization).  We accomplish that here by routing through `ensureLoggedIn()`
// first, and rendering the `dialog` view.

exports.authorization = [
  login.ensureLoggedIn(),
  server.authorization(function (clientID, redirectURI, done) {
    debug('authorizadion', clientID);

    store.hgetall('client-' + clientID, function (error, client) {
      if (error) {
        return done(error);
      }
      if (redirectURI !== client.redirect_uri) {
        return done('invalid redirect');
      } else {
        return done(null, client, redirectURI);
      }
    });
  }),
  function (req, res) {
    res.send(
      '<p>Hi ' + req.user.email + '</p>' +
      '<p><b>' + req.oauth2.client.client_name + '</b> is requesting access to your account.</p>' +
      '<p>Do you approve?</p>' +
      '<form action="/oauth2/authorize/decision" method="post">' +
      '<input name="transaction_id" type="hidden" value="' + req.oauth2.transactionID + '">' +
      '<div>' +
      '<input type="submit" value="Allow" id="allow">' +
      '<input type="submit" value="Deny" name="cancel" id="deny">' +
      '</div>' +
      '</form>'
    );
  }
];

// user decision endpoint
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application.  Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.

exports.decision = [
  login.ensureLoggedIn(),
  server.decision()
];


// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

exports.token = [
  passport.authenticate(['basic', 'oauth2-client-password'], {
    session: false
  }),
  server.token(),
  server.errorHandler()
];
