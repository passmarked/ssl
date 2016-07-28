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
    '-tls1_2',
    '-connect', address + ':' + (uri.port || 443),
    '-servername',
    uri.hostname

  ];

  // execute the actual process
  ssl.exec(args.join(' '), function(err, stdout, stderr) {

    // check for a error
    if(err) {

      // output to stderr
      payload.error('Something went wrong while checking for TLSv1.2 support');

      // done
      return fn(null);

    }

    // to string just in case
    stdout = (stdout || '').toString();
    stderr = (stderr || '').toString();

    // set the output
    var output = stdout + '\n' + stderr;

    // check if client connected
    if(output.toLowerCase().indexOf('connected(') != -1 && 
        output.toLowerCase().indexOf('handshake failure') == -1)
          return fn(null);

    // split up the lines
    var lines = output.split('\n');

    // build a code sample
    var build = payload.getSnippetManager().build(lines, -1, function(line) {
      
      // default is no
      return line.indexOf('connected(') != -1;

    });

    // sanity check
    if(!build) return fn(null);

    // add the vunerable rule
    payload.addRule({

      type:           'error',
      key:            'tls1.2',
      message:        'TLS v1.2 not supported'

    }, {

        display:      'code',
        message:      'The server $ does not have TLS v1.2 enabled',
        code:         build,
        identifiers:  [ address ]

      });

    // done !
    fn(null)

  });

};
