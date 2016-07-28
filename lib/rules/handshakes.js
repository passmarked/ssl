// pull in our modules
const url             = require('url');
const S               = require('string');
const childProcess    = require('child_process');
const async           = require('async');
const _               = require('underscore');
const clientConfig    = require('../../clients.json');

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, address, socket, fn) {

  // get the data
  var data = payload.getData();

  // only if SSL
  if(S( data.url.toLowerCase() ).startsWith("https") == false) 
    return fn(null);

  // parse the url
  var uri = url.parse( data.url );

  // the chipher checks
  var cipherChecks = {};

  // execute the actual process
  childProcess.exec("openssl ciphers 'ALL:eNULL'", {}, function(err, stdout, stderr) {

    // check the error
    if(err) {

      // output the rror
      payload.error('Something went wrong while trying to get all the ciphers', err);

      // done
      return fn(null);

    }

    // to string just in case
    stdout = (stdout || '').toString();
    stderr = (stderr || '').toString();

    // use the ciphers
    var ciphers = stdout.split(':');
    var keyCheck = new RegExp(/(.*?)\s+\:\s+(.*)/gim);

    // run each
    async.each(ciphers, function(cipher, cb) {

      // build the commands to send
      var args = [ 

        'echo',
        'QUIT',
        '|',
        '/usr/local/ssl/bin/openssl',
        's_client',
        '-cipher',
        '"' + cipher + '"',
        '-servername',
        uri.hostname,
        '-connect',
        address + ':' + (uri.port || 443)

      ];

      // debug
      payload.debug('Running: ' + args.join(' '))

      // execute the actual process
      childProcess.exec(args.join(' '), {}, function(err, stdout, stderr) {

        // get the full output
        var output = stdout + '\n' + stderr;

        // check the error
        if(err) {

          // output the rror
          payload.error('Something went wrong while trying to get all the ciphers', err);

        }

        // was this a error ?
        if(output.indexOf(':error:') != -1) {

          var msg = output.slice(output.indexOf(':error:'), output.length);
          msg = msg.slice(0, msg.lastIndexOf('\n'));

          cipherChecks[cipher] = msg.split(':')[5];

        } else {

          // set our response
          var outputKeys = (output || '').match(/(.*?)\:\s+(.*)\n/gim);
          var obj = {};

          for(var i = 0; i < outputKeys.length; i++) {

            var outputKey = S(outputKeys[i]).trim().s;

            var sections = outputKey.split(':');
            var key = S(sections[0] || '').trim().slugify().s;
            var value = S(sections[1] || '').trim().s;

            obj[key] = value;

          }

          cipherChecks[cipher] = obj;

        }

        // done with this call
        cb(null);

      });

    }, function(err) {

      // load in the client config

      console.log('done');
      console.dir(cipherChecks);

      // done
      fn(err);

    });

  });

};
