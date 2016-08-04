// pull in our modules
const url             = require('url');
const childProcess    = require('child_process');
const OpenSSL         = require('../certificates');

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
  if(data.url.toLowerCase().indexOf('https') != 0)
    return fn(null);

  // parse the url
  var uri = url.parse( data.url );

  // get the SSL
  var ssl = new OpenSSL(payload, address, socket);

  // build the commands to send
  var args = [ 

    'echo QUIT', 
    '|', 
    ssl.getExecutable(), 
    's_client', 
    '-CApath',
    '/etc/ssl/certs',
    '-cipher',
    'aNULL', 
    '-connect', address + ':' + (uri.port || 443),
    '-servername',
    uri.hostname

  ];

  // execute the actual process
  ssl.exec(args.join(' '), function(err, stdout, stderr) {

    // to string just in case
    stdout = (stdout || '').toString();
    stderr = (stderr || '').toString();

    // get the output
    var output = stdout + '\n' + stderr;

    // check if client connected
    if(output.toLowerCase().indexOf('connected(') == -1)
      return fn(null);

    // check if we just closed the pipe like Facebook.com
    if(output.toLowerCase().indexOf('errno') != -1)
      return fn(null);

    // check if we just closed the pipe like Facebook.com
    if(output.toLowerCase().indexOf('handshake failure') != -1)
      return fn(null);

    // split up the lines
    var lines = (output).split('\n')

    // build a code sample
    var build = payload.getSnippetManager().build( lines, -1, function(line) {

      if(line.indexOf('handshake failure') != -1)
        return true;
      if(line.indexOf('errno') != -1)
        return true;

      // default to no
      return false;

    });

    // add the vunerable rule
    payload.addRule({

      type:           'error',
      key:            'anonymous',
      message:        'Server has Anonymous ciphers enabled'

    }, {

        display:      'code',
        message:      'Anonymous ciphers should be enabled on $',
        code:         build,
        identifiers:  [ address ]

      });

    // done !
    fn(null);

  });

};
