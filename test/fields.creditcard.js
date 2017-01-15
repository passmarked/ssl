const assert      = require('assert');
const _           = require('underscore');
const fs          = require('fs');
const passmarked  = require('passmarked');
const testFunc    = require('../lib/rules/fields');

describe('fields', function() {

  describe('creditcards', function() {

    it('Should not return a error if no credit card info is present on HTTP', function(done) {

      // read in the html sample
      var content = fs.readFileSync('./samples/fields.creditcard.notsecure.missing.html');

      // handle the payload
      var payload = passmarked.createPayload({

        url: 'http://example.com'

      }, { log: { entries: [] } }, content.toString())

      testFunc(payload, function(err) {

        if(err) assert.fail('Something went wrong');
        var rules = payload.getRules();
        var rule = _.find(rules || [], function(item) { 

          return item.key === 'fields.creditcard'; 

        });
        if(rule)
          assert.fail('Was not expecting a error');

        // done
        done()

      });

    });

    it('Should not return a error if no credit card info is present on HTTPS', function(done) {

      // read in the html sample
      var content = fs.readFileSync('./samples/fields.creditcard.secure.missing.html');

      // handle the payload
      var payload = passmarked.createPayload({

        url: 'https://example.com'

      }, { log: { entries: [] } }, content.toString())

      testFunc(payload, function(err) {

        if(err) assert.fail('Something went wrong');
        var rules = payload.getRules();
        var rule = _.find(rules || [], function(item) { 

          return item.key === 'fields.creditcard'; 

        });
        if(rule)
          assert.fail('Was not expecting a error');

        // done
        done()

      });

    });

    it('Should return a error if creditcard is present on HTTP page', function(done) {

      // read in the html sample
      var content = fs.readFileSync('./samples/fields.creditcard.notsecure.html');

      // handle the payload
      var payload = passmarked.createPayload({

        url: 'http://example.com'

      }, { log: { entries: [] } }, content.toString())

      testFunc(payload, function(err) {

        if(err) assert.fail('Something went wrong');
        var rules = payload.getRules();
        var rule = _.find(rules || [], function(item) { 

          return item.key === 'fields.creditcard'; 

        });
        if(!rule)
          assert.fail('Was expecting a error');

        // done
        done()

      });

    });

    it('Should not return a error if creditcard is present on HTTPS page', function(done) {

      // read in the html sample
      var content = fs.readFileSync('./samples/fields.creditcard.secure.html');

      // handle the payload
      var payload = passmarked.createPayload({

        url: 'https://example.com'

      }, { log: { entries: [] } }, content.toString())

      testFunc(payload, function(err) {

        if(err) assert.fail('Something went wrong');
        var rules = payload.getRules();
        var rule = _.find(rules || [], function(item) { 

          return item.key === 'fields.creditcard'; 

        });
        if(rule)
          assert.fail('Was not expecting a error');

        // done
        done()

      });

    });

  });

});
