// pull in our modules
const url             = require('url');
const childProcess    = require('child_process');
const S               = require('string');
const OpenSSL         = require('../certificates');

/**
* Parse the regex
**/
var verificationRegex = new RegExp(/peer\s+signing\s+digest:\s+(.*)/gi);

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
    '-connect',
    address + ':' + (uri.port || 443),
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

    // get the output
    var output = stdout + '\n' + stderr;

    // check if client connected
    if(output.toLowerCase().indexOf('connected(') == -1)
      return fn(null);

    // get the matches
    var matches = output.match(/peer\s+signing\s+digest:\s+(.*)/gi); // verificationRegex.exec(output);

    // were we able to parse out a connection ?
    if(!matches) return fn(null);

    // get the code and message
    var hashLevel        = S( (matches[0] || '').toLowerCase().split(':')[1] ).trim().s;

    // if anything else than "0", signalling a unverified SSL certificate
    if(hashLevel == 'sha1') {

      // split up the lines
      var lines = output.split('\n');

      // build a code sample
      var build = payload.getSnippetManager().build(lines, -1, function(line) {
        
        return line.indexOf('peer signing digest') != -1;

      });

      // add the vunerable rule
      payload.addRule({

        type:           'error',
        key:            'sha1',
        message:        'SSL certificate signed using SHA1'

      }, {

          display:      'code',
          message:      'The certificate supplied by $ was signed by SHA1',
          code:         build,
          identifiers:  [ address ]

        });

    }

    // done !
    fn(null)

  });

};
