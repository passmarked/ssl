// modules
const assert        = require('assert');
const _             = require('underscore');
const passmarked    = require('passmarked');
const testFunc      = require('../lib/rules/recommend');
const Constants     = require('../lib/constants');
const moment        = require('moment');
const fs            = require('fs');

// checks warnings that we check for
describe('recommend', function() {

  // handle the error output
  it('Should not return a notice if url is already https', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

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
      var rule = _.find(rules, function(rule) { return rule.key == 'https.enabled' });

      if(rule) assert.fail('Was not expecting a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should return a notice if url is not https', function(done) {

    payload = passmarked.createPayload({

        url: 'http://example.com/'

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
      var rule = _.find(rules, function(rule) { return rule.key == 'https.enabled' });

      if(!rule) assert.fail('Was expecting a error');
      if(rule.type != 'notice') assert.fail('The rule was expected to be a notice');

      // done
      done();

    });

  });

});
