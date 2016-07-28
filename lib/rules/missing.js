const tls       = require('tls');
const net       = require('net');
const url       = require('url');
const _         = require('underscore');
const moment    = require('moment');
const async     = require('async');

/**
* Check the host of a certificate
**/
module.exports = exports = function(payload, address, client, fn) {

  // sanity check
  if(!client) return fn(null);

  // get the certificate
  var cert = client.getPeerCertificate(false);

  // if we got a certificate, this check is done...
  if(cert) return fn(null);

  // add the rule
  payload.addRule({

    type:         'error',
    message:      'No certificate supplied by web server',
    key:          'missing'

  }, {

    message:      'Certificate was not returned by $',
    identifiers:  [ address ]

  })

  // done
  fn(null);

};