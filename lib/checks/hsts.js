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
  var uri = url.parse( data.url )

};
