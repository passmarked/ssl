// pull in our modules
const url             = require('url');
const heartbleed      = require('heartbleed-check');
const S               = require('string');

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, address, client, fn) {

  // get the data
  var data = payload.getData()

  // only if SSL
  if(S( data.url.toLowerCase() ).startsWith("https") == false)
    return fn(null);

  // parse the url
  var uri = url.parse( data.url );

  // check if vunerable
  heartbleed.doCheck(uri.hostname, uri.port || 443, function(err, result) {

    // great so check it .. ?
    if(!err && (result || {}).code == 0) {

      // add the vunerable rule
      payload.addRule({

        type:     'critical',
        key:      'heartbleed',
        message:  'Vulnerability to OpenSSL Heartbleed attack'

      });

    }

    // send back all the rules
    fn(null)

  });

};