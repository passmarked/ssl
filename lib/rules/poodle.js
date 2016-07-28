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
  var data = payload.getData()

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
    '-connect',
    address + ':' + (uri.port || 443),
    '-ssl3',
    '-servername',
    uri.hostname

  ];

  // execute the actual process
  ssl.exec(args.join(' '), function(err, stdout, stderr) {

    // check for a error
    if(err) {

      // output to stderr
      payload.error('Something went wrong while checking for the POODLE attack', err);

      // done
      return fn(null);

    }

    // to string just in case
    stdout = (stdout || '').toString();
    stderr = (stderr || '').toString();

    // build the output to use
    var output = stdout + '\n' + stderr;

    // check if client connected
    if(output.toLowerCase().indexOf('connected(') == -1)
      return fn(null);

    if(output.indexOf('handshake failure') != -1)
      return fn(null);

    // split up the lines
    var lines = output.split('\n');

    // build a code sample
    var build = payload.getSnippetManager().build(lines, -1, function(line) {
      
      if(line.indexOf('handshake failure') != -1)
        return true;
      if(line.indexOf('rc4') != -1 && line.indexOf('ssl-session') != -1)
        return true;
      if(line.indexOf('connected(') != -1)
        return true;

      // stop them
      return false;

    });

    // add the vunerable rule
    payload.addRule({

      type:           'critical',
      key:            'poodle',
      message:        'Vulnerability to Poodle attack'

    }, {

        display:      'code',
        message:      'The server $ is vunerable to the Poodle attack',
        code:         build,
        identifiers:  [ address ]

      });

    // done !
    fn(null);

  });

};
