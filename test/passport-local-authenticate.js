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

  it('should generate backward compatible hashes', function(done) {
    // Used "password" as password
    var preHashed = {
      salt: '42aec8674b102c07bbcdef0eaed2a1764276d4d6cc298a7d868a033daa645b77',
      hash: 'd5193e434442df2e411f227015af0ce54cdff5c927f0153d70253a8b5e32733f9cb13edef22f49a47861f4a9f105c512cbb2d8537470aefe1982fe8d84452aba9db8fe98babd989197ecbea30e45b4086560103f67dc2e2330b54e94a20bb0569576e062d2ff183fbb60ef88fb1fbe0d939a3c33c63e2681fead7a8f28c93781d7090c854e2ee0bb4b6c8e86f108a68d458eb4cdfda695432b4784b48f2e9a879a1af851b40d446a3337cb0f3110e7a2f962b2659abbd819892997f9f4bbe2f6e218d33468caf7734a72a630d265546f9ca66332c419e569868f1b4a2cab20bb4de47bdfe55ceb22f8495abc9858da0d74240d3c8420622c9d4627ec788eedccb770d9b3c941ef9b786b661b88c3db720434b839c8fc9aee3d37e8160ba5e2b71b1845834fed813e54fa44acccda5337b1aa832fac36b98d30dd9e562c38dcfefbc0dc761bed3e718b38e3db6258e1795db851f15486eb7ecbb90cd5fb3b99af208584ef84abcb9808e24b955f6db9777d6628e5a42a66f2d1592800fd3a3e67537e89875edd6e421517069556c7f1ca225989b4c1e03386e90d35244231a75b202e1e859df5026387274fb7b3bbdec52a0897b55ccf7f38ae2304645ca60dc3139df44b5c1fa7f99c0b33c8c258edf4265c54710a5e39da8e688f86a051fc874d445c605592f006fd276b981bf316a8478f92e8d48e5887c8e3513e75f498bf'
    };

    auth.verify('password', preHashed, function(err, verified) {
      expect(err).to.not.exist;

      expect(verified).to.be.true;
      done();
    });
  })
});