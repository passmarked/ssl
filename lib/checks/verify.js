// pull in our modules
const url             = require('url');
const childProcess    = require('child_process');
const S               = require('string');
const OpenSSL         = require('../certificates');

/**
* Parse the regex
**/
var verificationRegex = new RegExp(/verify\s+return\s+code\:\s+(\d+)\s+\((.*?)\)/gi);

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, options, fn) {

  // pull out the params we can use
  var address     = options.address;
  var client      = options.client;
  var socket      = options.client;

  // get the data
  var data        = payload.getData();

  // only if SSL
  if(S( data.url.toLowerCase() ).startsWith("https") == false)
    return fn(null);

  // get the SSL
  var ssl = new OpenSSL(payload, address, socket);

  // parse the url
  var uri = url.parse( data.url );

  // build the commands to send
  var args = [ 

    'echo',
    'QUIT',
    '|',
    ssl.getExecutable(),
    's_client',
    '-verify',
    '20',
    '-connect',
    address + ':' + (uri.port || 443),
    '-CApath',
    '/etc/ssl/certs',
    '-servername',
    uri.hostname

  ];

  // execute the actual process
  ssl.exec(args.join(' '), function(err, stdout, stderr) {

    // check for a error
    if(err) {

      // output to stderr
      payload.error('Something went wrong while trying to verify the SSL certificate');

      // done
      return fn(null);

    }

    // to string just in case
    stdout = (stdout || '').toString();
    stderr = (stderr || '').toString();

    // build up the output
    var output = stdout + '\n' + stderr;

    // check if client connected
    if(output.toLowerCase().indexOf('connected(') == -1)
      return fn(null);

    // params to find
    var count       = 0;
    var code        = null;
    var errorMsg    = null;
    var matches     = null;

    // loop the matches found
    while ((matches = verificationRegex.exec(output)) !== null) {
      
      // increment our count
      count         = count + 1;

      // verify that we can find the match 
      if(!matches || !matches[1]) continue;

      // get the code and message
      code          = matches[1];
      errorMsg      = matches[2];

    }

    // split up the lines
    var lines = output.split('\n');

    // if anything else than "0", signaling a unverified SSL certificate
    if(count > 0 && code != '0') {

      // build a code sample
      var build = payload.getSnippetManager().build(lines, -1, function(line) {
        
        return line.indexOf('verify return code') != -1;

      });

      // add the vunerable rule
      payload.addRule({

        type:           'critical',
        key:            'verify',
        message:        'SSL certificate verification failed'

      }, {

          display:      'code',
          message:      'The $ certificate supplied by $ could not be verified, result was $',
          code:         build,
          identifiers:  [ address, S(errorMsg || '').trim().s ]

        });

    }

    // done !
    fn(null)

  });

};
