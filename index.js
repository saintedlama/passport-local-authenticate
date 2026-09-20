var crypto = require('crypto');
var semver = require('semver');
var scmp = require('scmp');

var ArgumentError = require('generaterr')('ArgumentError');

var pbkdf2DigestSupport = semver.gte(process.version, '0.12.0');

var DEFAULT_DIGEST_ALGORITHM = 'sha256';
var LEGACY_DIGEST_ALGORITHM = 'sha1';

module.exports = {
  hash :hash,
  verify : verify
};

function hash(password, options, next) {
  if (typeof options == 'function') {
    next = options;
    options = null;
  }

  options = defaultOptions(options);

  if (!password) {
    return next(new ArgumentError('Password argument is not specified'));
  }

  crypto.randomBytes(options.saltlen, function(err, buf) {
    if (err) { return next(err); }

    var salt = buf.toString(options.encoding);

    pbkdf2(password, salt, options.iterations, options.keylen, options.digestAlgorithm, function(err, hashRaw) {
      if (err) { return next(err); }

      var hash = new Buffer(hashRaw, 'binary').toString(options.encoding);

      next(null, { salt : salt, hash : hash });
    });
  });
}

function verify(password, credentials, options, next) {
  if (typeof options == 'function') {
    next = options;
    options = null;
  }

  options = defaultOptions(options);

  if (!password) {
    return next(new ArgumentError('password argument is not specified'));
  }

  if (!credentials) {
    return next(new ArgumentError('Credentials argument is not specified'));
  }

  if (!credentials.salt) {
    return next(new ArgumentError('Salt argument is not specified'));
  }

  if (!credentials.hash) {
    return next(new ArgumentError('Salt argument is not specified'));
  }

  verifyWithDigest(password, credentials, options, options.digestAlgorithm, function (err, verified) {
    if (err) { return next(err); }

    if (verified) { return next(null, true); }

    if (options.digestAlgorithm.toLowerCase() !== DEFAULT_DIGEST_ALGORITHM) {
      return next(null, false);
    }

    // Backward compatibility: credentials hashed before the default digest was
    // changed to sha256 use sha1. Retry verification with the legacy digest and,
    // on success, re-hash with the current (stronger) default so the caller can
    // persist the upgraded hash.
    verifyWithDigest(password, credentials, options, LEGACY_DIGEST_ALGORITHM, function (err, verified) {
      if (err) { return next(err); }

      if (!verified) { return next(null, false); }

      hash(password, options, function (err, rehashed) {
        if (err) { return next(err); }

        return next(null, true, rehashed);
      });
    });
  });
}

function verifyWithDigest(password, credentials, options, digestAlgorithm, callback) {
  pbkdf2(password, credentials.salt, options.iterations, options.keylen, digestAlgorithm, function (err, hashRaw) {
    if (err) { return callback(err); }

    var hash = new Buffer(hashRaw, 'binary').toString(options.encoding);

    return callback(null, scmp(hash, credentials.hash));
  });
}

function defaultOptions(options) {
  options = options || {};
  options.saltlen = options.saltlen || 32;
  options.encoding = options.encoding || 'hex';
  options.iterations = options.iterations || 25000;
  options.keylen = options.keylen || 512;
  options.digestAlgorithm = options.digestAlgorithm || DEFAULT_DIGEST_ALGORITHM;

  return options;
}

function pbkdf2(password, salt, iterations, keylen, digestAlgorithm, callback) {
  if (pbkdf2DigestSupport) {
    crypto.pbkdf2(password, salt, iterations, keylen, digestAlgorithm, callback);
  } else {
    crypto.pbkdf2(password, salt, iterations, keylen, callback);
  }
}

