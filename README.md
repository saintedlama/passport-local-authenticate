# Passport-Local-Authenticate
Encapsulates methods used to hash and verify user credentials for use in a passport-local strategy. This simplifies building username and password login with [Passport](http://passportjs.org).

[![Build Status](https://travis-ci.org/saintedlama/passport-local-authenticate.png?branch=master)](https://travis-ci.org/saintedlama/passport-local-authenticate)
[![Coverage Status](https://coveralls.io/repos/saintedlama/passport-local-authenticate/badge.png?branch=master)](https://coveralls.io/r/saintedlama/passport-local-authenticate?branch=master)


## Installation

    $ npm install passport-local-authenticate --save

## Usage

    var auth = require('passport-local-authenticate');

    auth.hash('password', function(err, hashed) {
      console.log(hashed.hash); // Hashed password
      console.log(hashed.salt); // Salt
    });

    auth.hash('password', function(err, hashed) {
      auth.verify('password', hashed, function(err, verified) {
        console.log(verified); // True, passwords match
      ));
    });

    auth.hash('password', function(err, hashed) {
      auth.verify('password2', hashed, function(err, verified) {
        console.log(verified); // False, passwords don't match
      ));
    });

## Options
*Attention!* Changing any of the hashing options (saltlen, iterations or keylen) in a production environment will prevent that existing users to authenticate!

* saltlen: specifies the salt length in bytes. Default: 32
* iterations: specifies the number of iterations used in pbkdf2 hashing algorithm. Default: 25000
* keylen: specifies the length in byte of the generated key. Default: 512
* encoding: specifies the encoding the generated salt and hash will be stored in. Defaults to 'hex'.

### Hash Algorithm
Passport-Local-Authenticate uses the pbkdf2 algorithm of the node crypto library. 
[Pbkdf2](http://en.wikipedia.org/wiki/PBKDF2) was chosen because platform independent
(in contrary to bcrypt). For every user a generated salt value is saved to make
rainbow table attacks even harder.

## License
Passport-Local-Authenticate is licenses under the [MIT license](http://opensource.org/licenses/MIT).
