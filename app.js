var
  debug = require('debug')('oauth'),
  express = require('express'),
  cookieParser = require('cookie-parser'),
  session = require('express-session'),
  redis = require("redis"),
  store = redis.createClient(),
  compress = require('compression')(),
  bodyParser = require('body-parser'),
  responseTime = require('response-time'),
  logger = require('morgan'),
  passport = require('passport'),
  path = require('path'),
  env = process.env.NODE_ENV || 'development',
  app = express(),
  core;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({ secret: 'keyboard cat', cookie: { secure: false }}));
app.use(passport.initialize());
app.use(passport.session());
app.use(compress);

if ('development' === env) {
  app.use(function (error, req, res, next) {
    res.render('error', {
      message: error.message,
      error: error
    });
  });
} else {
  app.locals.pretty = false;
}

app.use(function (req, res, next) {
  debug('URL', req.originalUrl);
  next();
});

core = require('./api').configure(app);

module.exports = app;
