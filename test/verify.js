// modules
const assert        = require('assert');
const _             = require('underscore');
const passmarked    = require('passmarked');
const testFunc      = require('../lib/checks/verify');
const Constants     = require('../lib/constants');
const moment        = require('moment');
const fs            = require('fs');

// checks warnings that we check for
describe('verify', function() {

  // handle the error output
  it('Should not return a error if we are able to verify the certificate', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/',
        testingStdout: fs.readFileSync('./samples/verify.good.txt').toString()

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

        getPeerCertificate: function() {

          return null;

        }

      },
      address:  '192.168.0.1'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a error
      if(rules.length > 0) assert.fail('Was not expecting a rule, but got ' + rules.length);

      // done
      done();

    });

  });

  // handle the error output
  it('Should not return a error if we were unable to connect', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/',
        testingStdout: fs.readFileSync('./samples/openssl.connect.txt').toString()

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

        getPeerCertificate: function() {

          return null;

        }

      },
      address:  '192.168.0.1'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a error
      if(rules.length > 0) assert.fail('Was not expecting a rule, but got ' + rules.length);

      // done
      done();

    });

  });

  // handle the error output
  it('Should return a error if any of the certificates was not able to verify', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/',
        testingStdout: fs.readFileSync('./samples/verify.multiple.txt').toString()

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

        getPeerCertificate: function() {

          return null;

        }

      },
      address:  '192.168.0.1'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a error
      var rule = _.find(rules, function(rule) { return rule.key == 'verify' });

      if(!rule) assert.fail('Was expecting a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should return a error if the certificate was not able to verify', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/',
        testingStdout: fs.readFileSync('./samples/verify.bad.txt').toString()

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

        getPeerCertificate: function() {

          return null;

        }

      },
      address:  '192.168.0.1'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a error
      var rule = _.find(rules, function(rule) { return rule.key == 'verify' });

      if(!rule) assert.fail('Was expecting a error');

      // done
      done();

    });

  });

});
