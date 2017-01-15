// pull in our modules
const url             = require('url');
const childProcess    = require('child_process');
const S               = require('string');
const OpenSSL         = require('../certificates');

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, options, fn) {

  // pull out the params we can use
  var address     = options.address;
  var algorithm   = options.algorithm;
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
    '-CApath',
    '/etc/ssl/certs',
    '-tls1',
    '-connect', address + ':' + (uri.port || 443),
    '-servername',
    uri.hostname

  ];

  // execute the actual process
  ssl.exec(args.join(' '), function(err, stdout, stderr) {

    // check for a error
    if(err) {

      // output to stderr
      payload.debug('checks', 'Something went wrong while checking for TLSv1 support');

      // done
      return fn(null);

    }

    // to string just in case
    stdout = (stdout || '').toString();
    stderr = (stderr || '').toString();

    // get the output
    var output = stdout + '\n' + stderr;

    // check if client connected
    if(output.toLowerCase().indexOf('connected(') != -1 && 
        output.toLowerCase().indexOf('handshake failure') == -1)
          return fn(null);

    // split up the lines
    var lines = output.split('\n');

    // build a code sample
    var build = payload.getSnippetManager().build(lines, -1, function(line) {
      
      if(line.indexOf('errno') != -1)
        return true;
      if(line.indexOf('connected(') != -1)
        return true;

      // default is no
      return false;

    });

    // add the vunerable rule
    payload.addRule({

      type:           'error',
      key:            'tls1',
      message:        'TLS v1 not supported'

    }, {

        display:      'code',
        message:      'The server $ does not have TLS v1 enabled',
        code:         build,
        identifiers:  [ address ]

      });

    // done !
    fn(null)

  });

};
