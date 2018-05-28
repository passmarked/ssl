const tls       = require('tls');
const net       = require('net');
const dns       = require('dns');
const url       = require('url');
const S         = require('string');
const _         = require('underscore');
const moment    = require('moment');
const async     = require('async');

/**
* Local checks we can do against a single
* instance of a certificate, this avoids
* doing a TLS connection for each of these
**/
const checks    = require('../checks');

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

  // only if SSL
  if(S( (data.url || '').toLowerCase() ).startsWith("https") == false) {

    // debug
    payload.debug('client', data.url + ' does not start with https so skipping');

    // done
    return fn(null);

  }

  // parse the url
  var uri = url.parse(data.url);

  // get the DNS entries for the host
  resolveIP(uri.hostname, function(err, addresses) {

    // did we receive a error ?
    if(err) {

      // debug
      payload.debug('client', 'Unable to get IP addresses for ' + uri.hostname)

      // report back :(
      return fn(err);

    }

    // cap the addresses at 5 per domain
    addresses = (addresses || []).slice(0, 5);

    // loop all the hostnames
    async.eachLimit(addresses, 2, function(address, cb) {

      // check if not already checked
      payload.isMentioned({

        key:      'ssl',
        rule:     'client',
        subject:  address

      }, function(err, mentioned) {

        // check if not already mentioned
        if(mentioned === true) {

          // debug
          payload.debug('fields', 'Already mentioned in the session, so skipping');

          // done
          return cb(null);

        }

        // the timer that will timeout the rule
        var timer = null;

        // create a quick to use single callback
        var callback = _.once(function(err) {

          // check if still here
          if(timer) {

            try {

              // clear the timer to save some processing cycles
              clearTimeout(timer);

              // clear from memory
              timer = null;

            } catch(err) {}

          }

          // mark as mentioned
          payload.mention({

            key:      'ssl',
            rule:     'client',
            subject:  address

          }, function() {

            // call our callback
            setImmediate(cb, err);

          });

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
          secureProtocol:     'TLSv1_method'

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

          // run each of our checks
          async.each(checks, function(checkFunc, cb) {

            // run each of the checks
            checkFunc(payload, {

              client:     client,
              address:    address

            }, function(err) {

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

          // output error for now
          console.dir(err)

          // throw back with our error
          callback(null);

        });

        /**
        * Resume so we can handle the data stream without 
        * creating a reference in memory
        **/
        client.resume();

        /**
        * Timeout after 10 seconds
        **/
        timer = setTimeout(callback, 1000 * 10);

      });

    }, function(err){

      // done
      setImmediate(fn, err);

    });

  });

};