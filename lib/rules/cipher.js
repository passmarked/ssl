// pull in our modules
const url             = require('url');
const childProcess    = require('child_process');
const S               = require('string');
const OpenSSL         = require('../exec');

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, address, socket, fn) {

  // get the data
  var data = payload.getData();

  // only if SSL
  if(S( data.url.toLowerCase() ).startsWith("https") == false)
    return fn(null);

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

  // parse the url
  var uri = url.parse( data.url )

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
    ciphers.join(','), 
    '-connect', 
    address + ':' + (uri.port || 443),
    '-servername',
    uri.hostname

  ];

  // execute the actual process
  ssl.exec(args.join(' '), function(err, stdout, stderr) {

    // step out if error
    if(err) {

      // output to stderr
      payload.error('Problem running the payload', err);

      // done
      return fn(null);

    }

    // get the output
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
    var lines = (stdout + '\n' + stderr).split('\n');

    // build a code sample
    build = payload.getSnippetManager().build(lines, -1, function(line) {
      
      if(line.indexOf('handshake failure') != -1)
        return true;
      if(line.indexOf('errno') != -1)
        return true;
      if(line.indexOf('connected(') != -1)
        return true;

      // default is nope
      return false;

    });

    // add the vunerable rule
    payload.addRule({

      type:           'error',
      key:            'cipher',
      message:        'Server has weaker ciphers enabled'

    }, {

        display:      'code',
        message:      'Server with the IP $ has weaker ciphers enabled, disable the following $',
        code:         build,
        identifiers:  [ address, ciphers.join(', ') ]

      });

    // done !
    fn(null);

  });

};
