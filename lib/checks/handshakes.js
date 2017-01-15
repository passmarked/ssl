// pull in our modules
const url             = require('url');
const S               = require('string');
const childProcess    = require('child_process');
const async           = require('async');
const _               = require('underscore');
const OpenSSL         = require('../certificates');
const mozillaSSL      = require('../../mozilla.json');

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, options, fn) {

  // get the ciphers
  var clientConfig    = (mozillaSSL || {}).configurations;
  var intermediate    = (clientConfig || {}).intermediate || {};
  var ciphers         = intermediate.ciphersuites;

  // pull out the params we can use
  var address     = options.address;
  var client      = options.client;
  var socket      = options.client;

  // get the data
  var data        = payload.getData();

  // only if SSL
  if(S( data.url.toLowerCase() ).startsWith("https") == false) 
    return fn(null);

  // parse the url
  var uri = url.parse( data.url );

  // get the SSL
  var ssl = new OpenSSL(payload, address, socket);

  // the chipher checks
  var cipherChecks = [];

  // run each
  async.each(ciphers, function(cipher, cb) {

    // build the commands to send
    var args = [ 

      'echo',
      'QUIT',
      '|',
      ssl.getExecutable(),
      's_client',
      '-cipher',
      '"' + cipher + '"',
      '-servername',
      uri.hostname,
      '-connect',
      address + ':' + (uri.port || 443)

    ];

    // debug
    console.log('Running: ' + args.join(' '))

    // execute the actual process
    ssl.exec(args.join(' '), function(err, stdout, stderr) {

      // get the full output
      var output = (stdout || '') + '\n' + (stderr || '');

      // check the error
      if(err) {

        // output the rror
        payload.debug('checks', 'Something went wrong while trying to get all the ciphers', err);

      }

      if(S(output.toLowerCase()).trim().s.indexOf('connected(0') === -1) {

        // add the item
        cipherChecks.push(cipher);

        // done
        console.log('--------$\n' + output + '\n$--------')

      }

      // done with this call
      cb(null);

    });

  }, function(err) {

    // load in the client config
    for(var i = 0; i < cipherChecks.length; i++) {

      console.dir(cipherChecks[i]);

    }

    // done
    fn(err);

  });

};
