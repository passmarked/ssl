// pull in our modules
const url             = require('url');
const S               = require('string');
const childProcess    = require('child_process');
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
  var uri = url.parse( data.url )

  // ask from the client
  // GET / HTTP/1.1
  // R

  // build the commands to send
  var args = [ 

    'echo',
    'QUIT',
    '|',
    ssl.getExecutable(),
    's_client',
    '-CApath',
    '/etc/ssl/certs',
    '-connect',
    address + ':' + (uri.port || 443),
    '-servername',
    uri.hostname

  ];

  // debug
  payload.debug('Running: ' + args.join(' '))

  // execute the actual process
  childProcess.exec(args.join(' '), {}, function(err, stdout, stderr) {

    // check the error
    if(err) {

      // output the rror
      payload.error('Something went wrong checking the FREAK attack', err);

      // done
      return fn(null);

    }

    // to string just in case
    stdout = (stdout || '').toString();
    stderr = (stderr || '').toString();

    // check if client connected
    if(stdout.toLowerCase().indexOf('secure renegotiation is supported') == -1)
      return fn(null);

    // right so we connected did we get a handshake failure
    if(stderr.toLowerCase().indexOf('get_server_hello') == -1)
      return fn(null);

    // split up the lines
    var lines = (stdout + '\n' + stderr).split('\n');

    // build a code sample
    var build = payload.getSnippetManager().build( lines, -1, function(line) {

      return line.toLowerCase().indexOf('secure renegotiation is') != -1;

    });

    // add the vunerable rule
    payload.addRule({

      type:         'error',
      key:          'renegotiation.client',
      message:      'Disable Client-Side SSL Renegotiation'

    }, {

        display:    'code',
        message:    '$ has client-side renegotiation enabled',
        code:       build

      })

    // done !
    fn(null);

  });

};
