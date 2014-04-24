var
  debug = require('debug')('oauth'),
  express = require('express'),
  cookieParser = require('cookie-parser'),
  session = require('express-session'),
  redis = require("redis"),
  session_store = redis.createClient(),
  compress = require('compression')(),
  bodyParser = require('body-parser'),
  responseTime = require('response-time'),
  http = require('http'),
  logger = require('morgan'),
  passport = require('passport'),
  path = require('path'),
  env = process.env.NODE_ENV || 'development',
  app = express(),
  core;

app.set('port', process.env.PORT || 3000);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({ secret: 'keyboard cat', cookie: { secure: false }}));
app.use(passport.initialize());
app.use(passport.session());
app.use(compress);

if ('development' === env) {
  app.use(logger('dev'));
} else {
  app.locals.pretty = false;
}

core = require('./api').configure(app);

http.createServer(app).listen(app.get('port'), function () {
  debug('API listening on port ' + app.get('port'));
});
