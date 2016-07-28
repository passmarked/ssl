// pull in our modules
const S               = require('string');

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, address, socket, fn) {

  // get the data
  var data = payload.getData();

  // only if SSL
  if(S( data.url.toLowerCase() ).startsWith("https") == true)
    return fn(null);

  // add the vunerable rule
  payload.addRule({

    type:       'notice',
    key:        'https.enabled',
    message:    'HTTPS is not enabled'

  });

  // done !
  fn(null);

};