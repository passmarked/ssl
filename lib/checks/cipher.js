// pull in our modules
const url             = require('url');
const childProcess    = require('child_process');
const S               = require('string');
const OpenSSL         = require('../certificates');
const async           = require('async');

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

  // parse the url
  var uri = url.parse( data.url );

  // get the SSL
  var ssl = new OpenSSL(payload, address, socket);

  // list of ciphers to test
  var ciphers = [

    'NULL',
    'EXPORT',
    'LOW',
    '3DES',
    'MD5',
    'RSK',
    'RC4'

  ];

  // run each of the given ciphers
  async.each(ciphers, function(cipher, cb) {

    // build the commands to send
    var args = [ 

      'echo', 
      'QUIT', 
      '|', 
      ssl.getExecutable(), 
      's_client', 
      '-CApath',
      '/etc/ssl/certs',
      '-cipher',
      [cipher].join(','), 
      '-connect', 
      address + ':' + (uri.port || 443),
      '-servername',
      uri.hostname

    ];

    // execute the actual process
    ssl.exec(args.join(' '), function(err, stdout, stderr) {

      // step out if error
      if(err) {

        // done
        return cb(null);

      }

      // get the output
      stdout = (stdout || '').toString();
      stderr = (stderr || '').toString();

      // get the output
      var output = stdout + '\n' + stderr;

      // check if client connected
      if(output.toLowerCase().indexOf('connected(') == -1)
        return cb(null);

      // check if we just closed the pipe like Facebook.com
      if(output.toLowerCase().indexOf('errno') != -1)
        return cb(null);

      // check if we just closed the pipe like Facebook.com
      if(output.toLowerCase().indexOf('handshake failure') != -1)
        return cb(null);

      // split up the lines
      var lines = (stdout + '\n' + stderr).split('\n');

      // build a code sample
      var build = payload.getSnippetManager().build(lines, -1, function(line) {
        
        if(line.indexOf('handshake failure') != -1)
          return true;
        if(line.indexOf('errno') != -1)
          return true;
        if(line.indexOf('connected(') != -1)
          return true;

        // default is nope
        return false;

      });

      // sanity check
      if(!build) return cb(null);

      // add the vunerable rule
      payload.addRule({

        type:           'warning',
        key:            'cipher',
        message:        'Server has weaker ciphers enabled'

      }, {

          display:      'code',
          message:      'Server with the IP $ has $ enabled which is seen as weak',
          code:         build,
          identifiers:  [ address, cipher ]

        });

      // done !
      cb(null);

    });

  }, function(err) {

    // done 
    fn(err);

  });

};
