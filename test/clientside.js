// modules
const assert        = require('assert');
const _             = require('underscore');
const passmarked    = require('passmarked');
const testFunc      = require('../lib/rules/clientside');
const Constants     = require('../lib/constants');
const moment        = require('moment');
const fs            = require('fs');

// checks warnings that we check for
describe('clientside', function() {

  // handle the error output
  it('Should not return error if no client side redirects are present on HTTP page (1 request)', function(done) {

    payload = passmarked.createPayload({

        url: 'http://example.com/',
        documents:  [

          {

            url:    'http://example.com',
            type:   'server'

          }

        ]

      }, {}, null);

    // execute the items
    testFunc(payload, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a error
      var rule = _.find(rules, function(rule) { return rule.key == 'clientside' });

      if(rule) assert.fail('Was not expecting a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should return a error if an HTTP page redirects clientside to HTTPS (2 requests)', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/',
        documents:  [

          {

            url:    'http://example.com',
            type:   'server'

          },
          {

            url:    'https://example.com',
            type:   'client'

          },
          {

            url:    'https://example.com',
            type:   'server'

          }

        ]

      }, {}, null);

    // execute the items
    testFunc(payload, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a error
      var rule = _.find(rules, function(rule) { return rule.key == 'clientside' });

      if(!rule) assert.fail('Was expecting a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should not return error if no client side redirects are present on HTTPS page (1 request)', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/',
        documents:  [

          {

            url:    'https://example.com',
            type:   'server'

          }

        ]

      }, {}, null);

    // execute the items
    testFunc(payload, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a error
      var rule = _.find(rules, function(rule) { return rule.key == 'clientside' });

      if(rule) assert.fail('Was not expecting a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should not return a error if an HTTP page redirects clientside to HTTP (2 requests)', function(done) {

    payload = passmarked.createPayload({

        url: 'http://example.com/test',
        documents:  [

          {

            url:    'http://example.com',
            type:   'server'

          },
          {

            url:    'http://example.com/test',
            type:   'client'

          },
          {

            url:    'http://example.com/test',
            type:   'server'

          }

        ]

      }, {}, null);

    // execute the items
    testFunc(payload, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a error
      var rule = _.find(rules, function(rule) { return rule.key == 'clientside' });

      if(rule) assert.fail('Was not expecting a error');

      // done
      done();

    });

  });

});
