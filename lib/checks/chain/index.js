const tls       = require('tls');
const net       = require('net');
const request   = require('request');
const url       = require('url');
const S         = require('string');
const _         = require('underscore');
const moment    = require('moment');
const async     = require('async');
const fs        = require('fs');
const util      = require('util');
const spawn     = require('child_process').spawn;
const pem       = require('pem');
const Constants = require('../../constants');
const OpenSSL   = require('../../certificates');

// require our methods to run 
const chainTestFuncs = [

  require('./missing'),
  require('./order'),
  require('./root'),
  require('./signature')

];

/**
* Check the valid date of a certificate
**/
module.exports = exports = function(payload, options, fn) {

  // pull out the params we can use
  var address     = options.address;
  var algorithm   = options.algorithm;
  var client      = options.client;

  // get the data
  var data        = payload.getData();

  // sanity check
  if(!client) return fn(null);

  // get the certificate
  var cert = client.getPeerCertificate(true);

  // just in case the peer does not provide a certificate ...
  if(!cert) return fn(null);

  // get the SSL
  var ssl = new OpenSSL(payload);

  // the variables we need to work with
  var downloadedPath  = [];
  var downloadedErr   = null;
  var suppliedPath    = [];
  var suppliedErr     = null;

  // download both paths
  async.parallel([

    /**
    * Generate our own path with path building
    **/
    function(cb) {

      // download path
      ssl.downloadPath(cert, 0, function(err, certs) {

        // parse the path given by the client
        if(certs)
          downloadedPath = certs;

        // set the error
        downloadedErr = err;

        // finish
        cb(null);

      });

    },

    /**
    * Generates and parses certificates that have been passed 
    * by the server which SSL will try and use and we will check.
    **/ 
    function(cb) {

      // first get all the certificates
      ssl.getPeerCertificates(cert, function(err, peers) {

        // set the error
        suppliedErr = err;

        // handle error if any
        if(err) return cb(null);

        // download path
        ssl.parseCertificates(peers, function(err, certs) {

          // parse the path given by the client
          if(certs)
            suppliedPath = certs;

          // set the error
          suppliedErr = err;

          // finish
          cb(null);

        });

      });

    }

  ], function(err) {

    // did we get a error ?
    if(err) {

      // output stderr
      payload.debug('checks', 'Problem downloading and walking paths of certificates', err);

      // done
      return fn(err);

    }

    // we need atleast one given certificate to check the chain ...
    if(suppliedPath.length === 0) {

      // nope out of here
      return fn(null);

    }

    // right so make a presentable chain we can use
    var presentableChain = ssl.buildPresentableChain(downloadedPath, suppliedPath);

    // run each of the rules
    async.each(chainTestFuncs, function(testFunc, cb) {

      // run the test
      testFunc(payload, _.extend({}, options, {

        expected:   downloadedPath,
        supplied:   suppliedPath,
        merged:     presentableChain,
        address:    address

      }), cb);

    }, function(err) {

      // finish
      fn(null);

    });
    
  });

};