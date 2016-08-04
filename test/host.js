// modules
const assert        = require('assert');
const _             = require('underscore');
const passmarked    = require('passmarked');
const testFunc      = require('../lib/checks/host');
const Constants     = require('../lib/constants');
const moment        = require('moment');

describe('host', function() {

  // handle the error output
  it('Should not return a rule if the given certificate was null', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

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
  it('Should not return a rule if the given certificate was false', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, {

      getPeerCertificate: function() {

        return false;

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
  it('Should not return a error if the given domain is part of the certificate', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

        getPeerCertificate: function() {

          return _.extend(require('../samples/certificate.host.json'), {

            valid_from:     moment().subtract(1, 'years').format(Constants.TLS_DATE_FORMAT),
            valid_to:       moment().add(1, 'years').format(Constants.TLS_DATE_FORMAT),
            subjectaltname: [

              'DNS:example.com', 'DNS:www.example.com'

            ].join(','),
            commonName:     'example.com'

          });

        }

      },
      address: '192.168.0.1'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'host'; });

      // check for a error
      if(rule) assert.fail('Was not expecting a rule');

      // done
      done();

    });

  });

  // handle the error output
  it('Should return a error if the given domain is not part of the certificate', function(done) {

    payload = passmarked.createPayload({

        url: 'https://example222.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

        getPeerCertificate: function() {

          return _.extend(require('../samples/certificate.host.json'), {

            valid_from:     moment().subtract(1, 'years').format(Constants.TLS_DATE_FORMAT),
            valid_to:       moment().add(1, 'years').format(Constants.TLS_DATE_FORMAT),
            subjectaltname: [

              'DNS:example.com', 'DNS:www.example.com'

            ].join(','),
            commonName:     'example.com'

          });

        }
        
      }

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'host'; });

      // check for a error
      if(!rule) assert.fail('Was expecting a rule');

      // done
      done();

    });

  });

  // handle the error output
  it('Should match wilcard subdomains if given on the certificate [www.example.com]', function(done) {

    payload = passmarked.createPayload({

        url: 'https://www.example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

        getPeerCertificate: function() {

          return _.extend(require('../samples/certificate.host.json'), {

            valid_from:     moment().subtract(1, 'years').format(Constants.TLS_DATE_FORMAT),
            valid_to:       moment().add(1, 'years').format(Constants.TLS_DATE_FORMAT),
            subjectaltname: [

              'DNS:example.com', 'DNS:*.example.com'

            ].join(','),
            commonName:     'example.com'

          });

        }

      },
      address: '192.168.0.1'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'host'; });

      // check for a error
      if(rule) assert.fail('Was not expecting a rule');

      // done
      done();

    });

  });

  // handle the error output
  it('Should match wilcard subdomains if given on the certificate [api.example.com]', function(done) {

    payload = passmarked.createPayload({

        url: 'https://api.example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

          getPeerCertificate: function() {

          return _.extend(require('../samples/certificate.host.json'), {

            valid_from:     moment().subtract(1, 'years').format(Constants.TLS_DATE_FORMAT),
            valid_to:       moment().add(1, 'years').format(Constants.TLS_DATE_FORMAT),
            subjectaltname: [

              'DNS:example.com', 'DNS:*.example.com'

            ].join(','),
            commonName:     'example.com'

          });

        }

      },
      address: '192.168.0.1'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'host'; });

      // check for a error
      if(rule) assert.fail('Was not expecting a rule');

      // done
      done();

    });

  });

  // handle the error output
  it('Should not allow a subdomain that does not match the DNS wildcard on a lower level [wrong.host.example.com]', function(done) {

    payload = passmarked.createPayload({

        url: 'https://wrong.host.example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

          getPeerCertificate: function() {

          return _.extend(require('../samples/certificate.host.json'), {

            valid_from:     moment().subtract(1, 'years').format(Constants.TLS_DATE_FORMAT),
            valid_to:       moment().add(1, 'years').format(Constants.TLS_DATE_FORMAT),
            subjectaltname: [

              'DNS:example.com', 'DNS:*.example.com'

            ].join(','),
            commonName:     'example.com'

          });

        }

      },
      address: '192.168.0.1'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'host'; });

      // check for a error
      if(!rule) assert.fail('Was expecting a rule');

      // done
      done();

    });

  });

  // handle the error output
  it('Should not allow a subdomain that does not match the DNS wildcard on a lower level [another.wrong.host.example.com]', function(done) {

    payload = passmarked.createPayload({

        url: 'https://another.wrong.host.example.com/'

      }, {}, null);

    // execute the items
    testFunc(payload, {

      client: {

          getPeerCertificate: function() {

          return _.extend(require('../samples/certificate.host.json'), {

            valid_from:     moment().subtract(1, 'years').format(Constants.TLS_DATE_FORMAT),
            valid_to:       moment().add(1, 'years').format(Constants.TLS_DATE_FORMAT),
            subjectaltname: [

              'DNS:example.com', 'DNS:*.example.com'

            ].join(','),
            commonName:     'example.com'

          });

        }

      },
      address: '192.168.0.1'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // should have one rule
      var rule = _.find(rules || [], function(item) { return item.key === 'host'; });

      // check for a error
      if(!rule) assert.fail('Was expecting a rule');

      // done
      done();

    });

  });

});