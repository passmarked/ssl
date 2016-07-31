const tls       = require('tls');
const net       = require('net');
const dns       = require('dns');
const url       = require('url');
const _         = require('underscore');
const moment    = require('moment');
const async     = require('async');

/**
* Local checks we can do against a single
* instance of a certificate, this avoids
* doing a TLS connection for each of these
**/
const checks    = require('./rules');

/**
* Returns the IP or the resolved IP
**/
var resolveIP = function(hostname, fn) {

  // if the host taget is a ip, skip it
  if(
    hostname.match(/[\d]+\.[\d]+\.[\d]+\.[\d]+/gi) ||
    hostname.match(/(([a-zA-Z0-9]{1,4}|):){1,7}([a-zA-Z0-9]{1,4}|:)/gi)) {

    // done
    return fn(null, [hostname]);

  } else {

    // return the resolved ips
    dns.resolve4(hostname, fn);

  }

};

/**
* Checks stats related to the certificate
**/
module.exports = exports = function(payload, fn) { 

  // get the data from the payload
  var data = payload.getData();

  // parse the url
  var uri = url.parse(data.url);

  // check if this page is SSL
  if(uri.protocol !== 'https:') return fn(null);

  // get the DNS entries for the host
  resolveIP(uri.hostname, function(err, addresses) {

    // cap the addresses at 10 per domain
    addresses = (addresses || []).slice(0, 5);

    // loop all the hostnames
    async.each(addresses, function(address, cb) {

      // the timer that will timeout the rule
      var timer = null;

      // create a quick to use single callback
      var callback = _.once(function(err) {

        // clear the timer to save some processing cycles
        clearTimeout(timer);

        // clear from memory
        timer = null;

        // call our callback
        cb(err);

      });

      // build the options
      var options = {

        isServer:           false,
        rejectUnauthorized: false,
        port:               uri.port || 443,
        host:               address,
        authorized:         false,
        servername:         uri.hostname,
        requestCert:        true,
        ciphers:            [

          'ECDHE-RSA-AES128-GCM-SHA256',
          // 'ECDHE-ECDSA-AES128-GCM-SHA256',
          'ECDHE-RSA-AES256-GCM-SHA384',
          // 'ECDHE-ECDSA-AES256-GCM-SHA384',
          'DHE-RSA-AES128-GCM-SHA256',
          'ECDHE-RSA-AES128-SHA256',
          'DHE-RSA-AES128-SHA256',
          'ECDHE-RSA-AES256-SHA384',
          'DHE-RSA-AES256-SHA384',
          'ECDHE-RSA-AES256-SHA256',
          'DHE-RSA-AES256-SHA256'

        ].join(':')

      };

      // upgrade to a TLS session
      var client = new tls.connect(options);

      // keep us sane :)
      client.setEncoding( 'utf8' );

      // do a quick sample of the time
      var started = new Date().getTime();

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
        
        // get the protocol to use
        var protocl   = client.getProtocol();

        // get the certificate information
        var cert      = client.getPeerCertificate();

        // run each of our checks
        async.each(checks, function(checkFunc, cb) {

          // run each of the checks
          checkFunc(payload, address, client, function(err) {

            // bubble up any errors we might get
            cb(err);

          });

        }, function(err) {

          // check if we should out the error ?
          if(err) {

            // output to stderr
            payload.error('Problem checking the TLS session', err);

          }

          try {

            // close the client
            client.close();

          } catch(err) {}

          // done
          callback(err);

        });

      })

      /**
      * Handle any errors that might come our way
      **/
      client.on('error', function( err ) {

        // output the error
        payload.error('Problem connecting to remote host', err);

        // throw back with our error
        callback(null);

      })

      /**
      * Handle the data to be sure we clear the buffer and don't hang
      **/
      client.on('data', function( data ) { /** We only listen to clear the buffer **/ });

      /**
      * Timeout after 10 seconds
      **/
      timer = setTimeout(callback, 1000 * 10);

    }, function(err){

      // done
      fn(err);

    });

  });

};