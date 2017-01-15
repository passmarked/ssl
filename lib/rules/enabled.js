// pull in our modules
const S     = require('string');
const url   = require('url');

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, fn) {

  // get the data
  var data = payload.getData();

  // only if SSL
  if(S( (data.url || '').toLowerCase() ).startsWith("https") == true) {

    // debugging
    payload.debug('enabled', 'Skipping enabled as HTTPS is done');

    // done
    return fn(null);

  }

  // parse the url
  var uri = url.parse(data.url);

  // add the vunerable rule
  payload.addRule({

    type:         'warning',
    key:          'enabled',
    message:      'HTTPS is not enabled'

  }, {

    message:      '$ does not have HTTPS enabled',
    identifiers:  [ uri.hostname ]

  });

  // done !
  fn(null);

};