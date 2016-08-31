// pull in our modules
const url             = require('url');
const S               = require('string');
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
  if(S( data.url.toLowerCase() ).startsWith("https") == false) 
    return fn(null);

  // get the SSL
  var ssl = new OpenSSL(payload, address, socket);

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
    '-connect',
    address + ':' + (uri.port || 443),
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

    // set the output
    var output = stdout + '\n' + stderr;

    // check if client connected
    if(output.toLowerCase().indexOf('connected(') == -1)
      return fn(null);

    // compile the pattern
    var pattern = new RegExp(/compression:\s+(.*)/gi);

    // parse it
    var matches = pattern.exec(output);

    // check if not null
    if(matches === null) return fn(null);
    if(matches === undefined) return fn(null);

    // get the compression
    var compressionCode = S((matches || [])[1] || 'none').trim().s.toLowerCase(); 

    // check if none
    if(compressionCode != 'none') {

      // split up the lines
      var lines = (stdout + '\n' + stderr).split('\n');

      // build a code sample
      var build = payload.getSnippetManager().build( lines, -1, function(line) {

        return pattern.exec(line) !== null;

      });

      // sanity check
      if(!build) return fn(null);

      // add the vunerable rule
      payload.addRule({

        type:           'error',
        key:            'compression',
        message:        'Disable TLS compression'

      }, {

          display:      'code',
          message:      '$ is vulnerable as TLS Compression is enabled',
          code:         build,
          identifiers:  [ address ]

        });

      // add the vunerable rule
      payload.addRule({

        type:           'critical',
        key:            'crime',
        message:        'Vulnerability to the CRIME attack was found'

      }, {

          display:      'code',
          message:      '$ is vulnerable as TLS Compression is enabled',
          code:         build,
          identifiers:  [ address ]

        });

    }

    // done !
    fn(null);

  });

};
