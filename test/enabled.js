const assert      = require('assert');
const _           = require('underscore');
const fs          = require('fs');
const passmarked  = require('passmarked');
const testFunc    = require('../lib/rules/enabled');

describe('enabled', function() {

  it('Should return a error if the user is not over HTTPS', function(done) {

    // handle the payload
    var payload = passmarked.createPayload({

      url: 'http://example.com'

    }, { log: { entries: [] } }, '')

    testFunc(payload, function(err) {

      if(err) assert.fail('Something went wrong');
      var rules = payload.getRules();
      var rule = _.find(rules || [], function(item) { return item.key === 'enabled'; });
      if(!rule) 
        assert.fail('Was expecting a error but got nothing');

      // done
      done()

    });

  });

  it('Should not return a error if the user is over HTTPS', function(done) {

    // handle the payload
    var payload = passmarked.createPayload({

      url: 'https://example.com'

    }, { log: { entries: [] } }, '')

    testFunc(payload, function(err) {

      if(err) assert.fail('Something went wrong');
      var rules = payload.getRules();
      var rule = _.find(rules || [], function(item) { return item.key === 'enabled'; });
      if(rule) 
        assert.fail('Was not expecting a error but got one');

      // done
      done()

    });

  });

});
