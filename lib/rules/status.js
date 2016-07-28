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
    '-status',
    '-tlsextdebug',
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

    // check if client connected
    if(stdout.toLowerCase().indexOf('connected(') == -1)
      return fn(null);

    // split up the lines
    var lines = (stdout + '\n' + stderr).split('\n');

    // check if the server has SNI configured
    if(stdout.toLowerCase().indexOf('tls server extension "server name"') === -1) {

      // build a code sample
      var build = payload.getSnippetManager().build( lines, -1, function(line) {

        return line.toLowerCase().indexOf('tls server extension "server name"') != -1;

      });

      // add the vunerable rule
      payload.addRule({

        type:             'warning',
        key:              'sni',
        message:          'Enable SNI'

      }, {

          display:        'code',
          message:        '$ does not have SNI enabled',
          code:           build,
          identifiers:    [ address ]

        });

    }

    // match OSCP
    var oscpResult = stdout.match(/OCSP\s+Response\s+Status\:\s+(.*)/gi);

    // check if the server has SNI configured
    if(oscpResult) {

      // get the code
      var oscpCode = oscpResult[1];

      // if not success full ?
      if((oscpCode || '').toLowerCase().indexOf('success') != 0) {

        // build a code sample
        var build = payload.getSnippetManager().build( lines, -1, function(line) {

          return line.toLowerCase().indexOf('ocsp response status') != -1;

        });

        // add the vunerable rule
        payload.addRule({

          type:         'critical',
          key:          'oscp.cert',
          message:      'OCSP status did not report as successful'

        }, {

          message:      'The server at $ responded with the OSCP status $',
          identifiers:  [ address, oscpCode ],
          code:         build,
          display:      'code'

        });

      }

    } else {

      // add the vunerable rule
      payload.addRule({

        type:         'warning',
        key:          'ocsp',
        message:      'OCSP stapling is not configured'

      }, {

        message:      'The server at $ did not report having OCSP enabled',
        identifiers:  [ address ],
        code:         build,
        display:      'code'

      });

    }

    // get the OCP status
    var ocpStatus = stdout.match(/ocsp\s+response\:\s+(.*)/gi);

    // check if we found the status
    if(ocpStatus) {

      // check if revoked 
      if((ocpStatus[1] || '').toLowerCase().indexOf('revoked')  != -1) {

        // build a code sample
        var build = payload.getSnippetManager().build( lines, -1, function(line) {

          return line.toLowerCase().indexOf('ocsp response') != -1;

        });

        // add the vunerable rule
        payload.addRule({

          type:           'critical',
          key:            'ocsp.cert',
          message:        'OCSP reports that certificate is revoked'

        }, {

            display:      'code',
            message:      '$ reported $ as OSCP status',
            code:         build,
            identifiers:  [ address, ocpStatus[1] ]

          });

      }

    }

    // done !
    fn(null);

  });

};
