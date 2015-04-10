var expect = require('chai').expect;
var auth = require('../');

describe('passportLocalAuthenticate', function () {
  it('should export a "hash" function', function () {
    expect(auth.hash).to.be.a('function');
  });

  it('should export a "verify" function', function () {
    expect(auth.verify).to.be.a('function');
  });

  it('should hash a password and pass hash with salt to callback', function (done) {
    auth.hash('password', function(err, hashed) {
      expect(err).to.not.exist;

      expect(hashed).to.exist;
      expect(hashed.salt).to.exist;
      expect(hashed.hash).to.exist;

      done();
    });
  });

  it('should hash and verify a password', function (done) {
    auth.hash('password', function(err, hashed) {
      expect(err).to.not.exist;

      auth.verify('password', hashed, function(err, verified) {
        expect(err).to.not.exist;

        expect(verified).to.be.true;
        done();
      });
    });
  });

  it('should not verify non matching passwords', function (done) {
    auth.hash('password', function(err, hashed) {
      expect(err).to.not.exist;

      auth.verify('password2', hashed, function(err, verified) {
        expect(err).to.not.exist;

        expect(verified).to.be.false;
        done();
      });
    });
  });
});