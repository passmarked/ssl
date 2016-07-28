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
    '-cipher',
    'EXPORT',
    '-servername',
    uri.hostname

  ];

  // execute the actual process
  ssl.exec(args.join(' '), function(err, stdout, stderr) {

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

    // get the output
    var output = stdout + '\n' + stderr;

    // check if client connected
    if(output.toLowerCase().indexOf('connected(') == -1)
      return fn(null);

    // right so we connected did we get a handshake failure
    if(output.toLowerCase().indexOf('get_server_hello') != -1)
      return fn(null);

    // split up the lines
    var lines = output.split('\n');

    // build a code sample
    var build = payload.getSnippetManager().build( lines, -1, function(line) {

      return line.toLowerCase().indexOf('connected(') != -1;

    })

    // add the vunerable rule
    payload.addRule({

      type:           'critical',
      key:            'freak',
      message:        'Vulnerability to OpenSSL FREAK attack'

    }, {

        display:      'code',
        message:      'Server at $ is vulnerability to the FREAK attack',
        code:         build,
        identifiers:  [ address ]

      })

    // done !
    fn(null);

  });

};
