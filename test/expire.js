// modules
const assert        = require('assert');
const _             = require('underscore');
const passmarked    = require('passmarked');
const testFunc      = require('../lib/rules/expire');
const Constants     = require('../lib/constants');
const moment        = require('moment');

describe('expire', function() {

  // handle the error output
  it('Should not return a rule if the given certificate was null', function(done) {

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
      if(rules.length > 0) assert.fail('Was not expecting a rule, but got ' + rules.length);

      // done
      done();

    });

  });

  // handle the error output
  it('Should not return a rule if the given certificate was blank', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return {};

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
  it('Should not return a rule if the given certificate had only a subject', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return { subject: {} };

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
  it('Should return a error if the certificate has expired', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return require('../samples/certificate.expire.json');

      }

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'expired'; });

      // check for a error
      if(!rule) assert.fail('Was expecting a rule');

      // done
      done();

    });

  });

  // handle the error output
  it('Should show that certificate expires today in message', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return _.extend(require('../samples/certificate.expire.json'), {

          valid_from: moment().subtract(256, 'days').format(Constants.TLS_DATE_FORMAT),
          valid_to:   moment().format(Constants.TLS_DATE_FORMAT)

        });

      }

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'expired'; });

      // check for a error
      if(!rule) assert.fail('Was expecting a rule');

      // check if it mentions "today"
      if(rule.occurrences[0].message.toLowerCase().indexOf('today') === -1)
        assert.fail('Error should mention that the certificate expires today');

      // done
      done();

    });

  });

  // handle the error output
  it('Should return a warning if the given certificate expires in a less than a month', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return _.extend(require('../samples/certificate.expire.json'), {

          valid_from: moment().subtract(200, 'days').format(Constants.TLS_DATE_FORMAT),
          valid_to:   moment().add(20, 'days').format(Constants.TLS_DATE_FORMAT)

        });

      }

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'expire'; });

      // check for a error
      if(!rule) assert.fail('Was expecting a rule');
      if(rule.type != 'warning') assert.fail('Warning was expected');

      // done
      done();

    });

  });

  // handle the error output
  it('Should return a error if the given certificate expires in a less than a 2 weeks', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return _.extend(require('../samples/certificate.expire.json'), {

          valid_from: moment().subtract(200, 'days').format(Constants.TLS_DATE_FORMAT),
          valid_to:   moment().add(4, 'days').format(Constants.TLS_DATE_FORMAT)

        });

      }

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'expire'; });

      // check for a error
      if(!rule) assert.fail('Was expecting a rule');
      if(rule.type != 'error') assert.fail('Error was expected');

      // done
      done();

    });

  });

  // handle the error output
  it('Should not return a error if the given certificate is still valid and more than a month from expire', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, '192.168.0.1', {

      getPeerCertificate: function() {

        return _.extend(require('../samples/certificate.expire.json'), {

          valid_from: moment().subtract(100, 'days').format(Constants.TLS_DATE_FORMAT),
          valid_to:   moment().add(200, 'days').format(Constants.TLS_DATE_FORMAT)

        });

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

});
