// modules
const assert        = require('assert');
const tls           = require('tls');
const _             = require('underscore');
const passmarked    = require('passmarked');
const testFunc      = require('../lib/rules/chain');
const Constants     = require('../lib/constants');
const moment        = require('moment');
const fs            = require('fs');
const dns           = require('dns');

/**
* Wrap for a secure client connection
**/
var execSecureConnection = function(payload, params, fn) {

  // get the dns
  dns.resolve4(params.servername, function(err, ips) {

    // build the options
    var options = _.extend({

      isServer:           false,
      rejectUnauthorized: false,
      port:               443,
      authorized:         false,
      requestCert:        true,
      host:               ips[0]

    }, params);

    // upgrade to a TLS session
    var client = new tls.connect(options);

    // keep us sane :)
    client.setEncoding( 'utf8' );

    /**
    * handle the plain socket connection
    **/
    client.on('connect' , function() {
      
      /**
      * The socket connected, but we're waiting for the handshake
      * where the certificate is returned with the event - "secureConnect"
      **/

    });

    /**
    * Handle the handshake of the TLS connection
    **/
    client.on('secureConnect', function() {

      // execute the items
      testFunc(payload, options.host, client, function(err) {

        // did we get a error
        if(err) assert.fail('Got a JS error from the rule');

        // done
        fn(null, payload);

        try {

          // close connection
          client.close();

        } catch(err) {}

      });

    })

    /**
    * Handle any errors that might come our way
    **/
    client.on('error', function( err ) {

      // output the error
      assert.fail('Problem connecting to remote host');

      // throw back with our error
      fn(err);

    })

    /**
    * Handle the data to be sure we clear the buffer and don't hang
    **/
    client.on('data', function(data) {});

  });

};

// checks warnings that we check for
describe('chain', function() {

  // handle the error output
  it('Should return the missing error if we are missing a certificate from the chain', function(done) {

    // the payload
    var payload = passmarked.createPayload({

        url: 'https://incomplete-chain.badssl.com/'

    }, {}, null);

    // build the options
    execSecureConnection(payload, {
        
      servername:         'incomplete-chain.badssl.com'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a missing certificate in the chain
      var rule = _.find(rules || [], function(item) {

        // check the rule key
        return item.key === 'chain.missing';

      });

      // do we have a rule ?
      if(!rule) assert.fail('Expected a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should not return a error if the chain is complete', function(done) {

    // the payload
    var payload = passmarked.createPayload({

        url: 'https://badssl.com/'

    }, {}, null);

    // build the options
    execSecureConnection(payload, {
        
      servername:         'badssl.com'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a missing certificate in the chain
      var rule = _.find(rules || [], function(item) {

        // check the rule key
        return item.key === 'chain.missing';

      });

      // do we have a rule ?
      if(rule) assert.fail('Did not expect a error');

      // done
      done();

    });

  });

  // handle the error output
  it('Should give back the signature if is sha1', function(done) {

    // the payload
    var payload = passmarked.createPayload({

        url: 'https://sha1-2016.badssl.com/'

    }, {}, null);

    // build the options
    execSecureConnection(payload, {
        
      servername:         'sha1-2016.badssl.com'

    }, function(err) {

      // did we get a error
      if(err) assert.fail('Got a JS error from the rule');

      // get the rules
      var rules = payload.getRules();

      // check for a missing certificate in the chain
      var rule = _.find(rules || [], function(item) {

        // check the rule key
        return item.key === 'chain.weak';

      });

      // do we have a rule ?
      if(!rule) assert.fail('Expected a error');

      // done
      done();

    });

  });

});
