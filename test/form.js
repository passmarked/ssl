const assert      = require('assert');
const _           = require('underscore');
const fs          = require('fs');
const passmarked  = require('passmarked');
const testFunc    = require('../lib/rules/form');

describe('form', function() {

  it('Should return a error for the external domain', function(done) {

    // read in the html sample
    var content = fs.readFileSync('./samples/form.insecure.html');

    // handle the payload
    var payload = passmarked.createPayload({

      url: 'https://test.com'

    }, { log: { entries: [] } }, content.toString())

    testFunc(payload, function(err) {

      if(err) assert.fail('Something went wrong');
      var rules = payload.getRules();
        var rule = _.find(rules || [], function(item) { 

          return item.key === 'form.external'; 

        });
        if(!rule)
          assert.fail('Was expecting a error');
      // done
      done()

    });

  });

  it('Should return a error for the internal domain', function(done) {

    // read in the html sample
    var content = fs.readFileSync('./samples/form.insecure.html');

    // handle the payload
    var payload = passmarked.createPayload({

      url: 'https://example.com'

    }, { log: { entries: [] } }, content.toString())

    testFunc(payload, function(err) {

      if(err) assert.fail('Something went wrong');
      var rules = payload.getRules();
        var rule = _.find(rules || [], function(item) { 

          return item.key === 'form.internal'; 

        });
        if(!rule)
          assert.fail('Was expecting a error');
      // done
      done()

    });

  });

  it('Should not return a error if the page is secure and the form is secure', function(done) {

    // read in the html sample
    var content = fs.readFileSync('./samples/form.secure.html');

    // handle the payload
    var payload = passmarked.createPayload({

      url: 'https://example.com'

    }, { log: { entries: [] } }, content.toString())

    testFunc(payload, function(err) {

      if(err) assert.fail('Something went wrong');
      var rules = payload.getRules();
      if(rules.length > 0) 
        assert.fail('Was not expecting a error');
      // done
      done()

    });

  });

  it('Should return a error if the page is secure and the form is unsecure', function(done) {

    // read in the html sample
    var content = fs.readFileSync('./samples/form.insecure.html');

    // handle the payload
    var payload = passmarked.createPayload({

      url: 'https://example.com'

    }, { log: { entries: [] } }, content.toString())

    testFunc(payload, function(err) {

      if(err) assert.fail('Something went wrong');
      var rules = payload.getRules();
      if(rules.length <= 0) 
        assert.fail('Was expecting a error');
      // done
      done()

    });

  });

  it('Should just skip if the page is over http://', function(done) {

    // read in the html sample
    var content = fs.readFileSync('./samples/form.secure.html');

    // handle the payload
    var payload = passmarked.createPayload({

      url: 'http://example.com'

    }, { log: { entries: [] } }, content.toString())

    testFunc(payload, function(err) {

      if(err) assert.fail('Something went wrong');
      var rules = payload.getRules();
      if(rules.length > 0) 
        assert.fail('Was not expecting a error');
      // done
      done()

    });

  });

  it('Should ignore if using special attributes like (#, /, //, javascript:void(0);, blank)', function(done) {

    // read in the html sample
    var content = fs.readFileSync('./samples/form.ignored.html');

    // handle the payload
    var payload = passmarked.createPayload({

      url: 'http://example.com'

    }, { log: { entries: [] } }, content.toString())

    testFunc(payload, function(err) {

      if(err) assert.fail('Something went wrong');
      var rules = payload.getRules();
      if(rules.length > 0) 
        assert.fail('Was not expecting a error');
      // done
      done()

    });

  });

});
