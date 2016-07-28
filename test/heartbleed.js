// modules
const assert        = require('assert');
const _             = require('underscore');
const passmarked    = require('passmarked');
const testFunc      = require('../lib/rules/heartbleed');
const Constants     = require('../lib/constants');
const moment        = require('moment');
const fs            = require('fs');

// checks warnings that we check for
describe('heartbeat', function() {

  this.timeout(5000);

  // handle the error output
  it('Should not return a error if heartbeat is not turned on', function(done) {

    var payload = passmarked.createPayload({

        url: 'https://google.com/',
        testingStdout: fs.readFileSync('./samples/heartbeat.good.txt').toString()

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
      var rule = _.find(rules, function(rule) { return rule.key == 'sni' });

      if(rule) assert.fail('Was not expecting a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should not return a error if we were unable to connect', function(done) {

    var payload = passmarked.createPayload({

        url: 'https://google.com/',
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

  /**
  * Will move our code over based from the code on the module, then we'll be able to 
  * test based on the TLS content that we test
  **/
  // handle the error output
  /* it('Should return a error if the heartbeat TLS extension is present', function(done) {

    var payload = passmarked.createPayload({

        url: 'https://google.com/',
        testingStdout: fs.readFileSync('./samples/heartbeat.bad.txt').toString()

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
      var rule = _.find(rules, function(rule) { return rule.key == 'heartbeat' });

      if(!rule) assert.fail('Was expecting a error');

      // done
      done();

    });

  }); */

});
