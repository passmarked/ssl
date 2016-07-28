// modules
const assert        = require('assert');
const _             = require('underscore');
const passmarked    = require('passmarked');
const testFunc      = require('../lib/rules/freak');
const Constants     = require('../lib/constants');
const moment        = require('moment');
const fs            = require('fs');

// checks warnings that we check for
describe('freak', function() {

  // handle the error output
  it('Should not return the error if FREAK is exploitable', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/',
        testingStdout: fs.readFileSync('./samples/freak.good.txt').toString()

      }, {}, null);

    // execute the items
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return null;

      }

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
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return null;

      }

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
  it('Should return a error if FREAK is configured', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/',
        testingStdout: fs.readFileSync('./samples/freak.bad.txt').toString()

      }, {}, null);

    // execute the items
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return null;

      }

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a error
      var rule = _.find(rules, function(rule) { return rule.key == 'freak' });

      if(!rule) assert.fail('Was expecting a error');

      // done
      done();

    });

  });

});
