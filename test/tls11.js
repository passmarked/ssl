// modules
const assert        = require('assert');
const _             = require('underscore');
const passmarked    = require('passmarked');
const testFunc      = require('../lib/checks/tlsv11');
const Constants     = require('../lib/constants');
const moment        = require('moment');
const fs            = require('fs');

// checks warnings that we check for
describe('tlsv1.1', function() {

  // handle the error output
  it('Should return a error if tls1.1 does not connect', function(done) {

    var payload = passmarked.createPayload({

        url: 'https://example.com/',
        testingStdout: fs.readFileSync('./samples/tls11.bad.txt').toString()

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
      var rule = _.find(rules, function(rule) { return rule.key == 'tls1.1' });
      if(!rule) assert.fail('Was expecting a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should return a error if we were unable to connect', function(done) {

    var payload = passmarked.createPayload({

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
      var rule = _.find(rules, function(rule) { return rule.key == 'tls1.1' });
      if(!rule) assert.fail('Was expecting a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should not return a error if the tls1.1 was able to connect', function(done) {

    var payload = passmarked.createPayload({

        url: 'https://example.com/',
        testingStdout: fs.readFileSync('./samples/tls11.good.txt').toString()

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
      var rule = _.find(rules, function(rule) { return rule.key == 'tls1.1' });
      if(rule) assert.fail('Was not expecting a error');

      // done
      done();

    });

  });

});
