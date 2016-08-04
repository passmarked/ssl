const tls       = require('tls');
const net       = require('net');
const S         = require('string');
const url       = require('url');
const _         = require('underscore');
const moment    = require('moment');
const async     = require('async');

/**
* Check the host of a certificate
**/
module.exports = exports = function(payload, options, fn) {

  // pull out the params we can use
  var address     = options.address;
  var algorithm   = options.algorithm;
  var client      = options.client;
  var socket      = options.client;

  // get the data
  var data        = payload.getData();

  // get the certificate
  var cert        = client.getPeerCertificate(false);

  // check if https
  if(S(data.url || '').trim().s.toLowerCase().indexOf('http://') === 0)
    return fn(null);

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