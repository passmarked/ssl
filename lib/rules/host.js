const tls       = require('tls');
const net       = require('net');
const url       = require('url');
const _         = require('underscore');
const moment    = require('moment');
const async     = require('async');
const S         = require('string');

/**
* Check the host of a certificate
**/
module.exports = exports = function(payload, address, client, fn) {

  // get payload data
  var data  = payload.getData();

  // parse the url
  var uri   = url.parse(data.url);

  // sanity check
  if(!client) return fn(null);

  // get the certificate
  var cert = client.getPeerCertificate(false);

  // just in case the peer does not provide a certificate ...
  if(!cert) return fn(null);

  // extract a few params to use
  var subject       = cert.subject  || {};
  var commonName    = subject.CN    || subject.cn   || cert.commonName   || null;
  var org           = subject.O     || subject.o    || cert.organization || null;
  var altnames      = (cert.subjectaltname || '').split(',');
  var domains       = [];

  // must be a array
  if(Array.isArray(altnames) === true) {

    // loop and add all the domains
    for(var i = 0; i < altnames.length; i++) {

      // get a local reference to work with
      var altname = S( altnames[i] || '' ).trim().s;

      // check that the altname was not empty
      if( S( altname || '' ).isEmpty() === true ) continue;

      // check if this is a DNS entry
      if(altname.toLowerCase().indexOf('dns:') != 0 && 
          altname.toLowerCase().indexOf('ip:') != 0) continue;

      // get the domain variable we will be adding
      var domain = altname.split(':')[1].toLowerCase();

      // add to the list then
      if(domains.indexOf(domain) === -1) {

        // add the unique name
        domains.push( domain );

      }

    }

  }

  // and then add the common name
  if( S(commonName).isEmpty() !== true ) {

    // get the domain to add
    var domain = commonName.toLowerCase();

    // should not be in list already
    if(domains.indexOf(domain) === -1) {
      
      // add our unique domain
      domains.push( domain );

    }

  }

  // console.log(JSON.stringify(cert, null, 2));

  // the altname we are using for this request
  var currentAltName = null;
  var sections       = uri.hostname.split('.');

  // check if the given hostname validates according to certificate
  for(var i = 0; i < domains.length; i++) {

    // local reference
    var patterns = domains[i].split('.');

    // flag if we had any failures ?
    var success = true;

    // split the domain
    for(var a = 0; a < sections.length; a++) {

      // check if there is a item in that pattern slot
      if(patterns[a] !== '*' && 
          patterns[a] != sections[a]) {

        // mark as false ...
        success = false;

        // stop !
        break;

      }

    }

    // check if the regex matches
    if(success == true) {

      // found it !
      currentAltName = domains[i];

      // break the loop
      break;

    }

  }

  if( currentAltName === null ) {

    // add the rule
    payload.addRule({

      message:      'Certificate did not match hostname',
      type:         'error',
      key:          'host'

    }, {

      message:      'Found $ valid hostnames from $ but $ was not one of them. Valid hosts include: $',
      identifiers:  [ domains.length, address, uri.hostname, domains.join(', ') ]

    });

  }

  // finish strong
  fn(null);

};