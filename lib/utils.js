const childProcess    = require('child_process');
const spawn           = require('child_process').spawn;
const S               = require('string');
const os              = require('os');
const path            = require('path');
const pem             = require('pem');
const crypto          = require('crypto');
const async           = require('async');
const _               = require('underscore');
const fs              = require('fs');
const request         = require('request');

// keep track of root certificates
if(!global.PASSMARKED_ROOT_CERTS) global.PASSMARKED_ROOT_CERTS = [];

module.exports = exports = function(logger) {

  /**
  * Object to return
  **/
  var SSL = {};

  /** 
  * Cache of root certificates
  **/ 
  var roots = [];

  /**
  * Returns the exec from bin
  **/
  SSL.getSSLExecutable = function(version) {

    return '/usr/local/ssl/bin/openssl';

  };

  /**
  * Matches a regex against a string returns the result else null
  **/
  SSL.extractVariable = function(text, pattern) {

    // set the matches
    var matches = new RegExp(pattern).exec(text || '');

    // did we find any ?
    if(matches && matches.length > 1) {
      return matches[1];
    }

    // default
    return null;

  };

  /**
  * Executes a investigation via OPENSSL on CRT properties
  **/
  SSL.getPEMInformation = function(pemFormat, fn) {

    // the singleton of the callback to call
    var callback = _.once(fn);

    // handle the util
    var proc = spawn('openssl', [

      'x509',
      '-noout',
      '-text'

    ]);

    // chunks we got
    var chunks  = [];
    var err     = null;
    var timer   = null;

    // add any chunks we got
    proc.stdout.on('data', function(data) { 

      chunks.push(data);

    });

    // handle any errors we found
    proc.stderr.on('data', function(data) {

      // set as the error
      err = new Error(data);

    });

    // handle on close
    proc.on('close', function(code) {

      // clear the timeout
      if(timer) clearTimeout(timer);

      // done
      callback(err, Buffer.concat(chunks || []).toString());

    });

    // write to the stream
    proc.stdin.write(pemFormat);
    proc.stdin.end();

    // timeout if any
    timer = setTimeout(function() {

      // done
      callback(new Error('Timeout'));

    }, 1000 * 5);

  };

  /**
  * Converts a certificate in DER format to PEM
  **/
  SSL.convertDERtoPEM = function(derFormat, fn) {

    // check if not already in PEM format
    if(derFormat && derFormat.toString().toLowerCase().indexOf('-----begin') === 0) {

      // just return it
      return fn(null, derFormat.toString());

    }

    // the singleton of the callback to call
    var callback = _.once(fn);

    // handle the util
    var proc = spawn(SSL.getSSLExecutable(), [

      'x509',
      '-inform',
      'der'

    ]);

    // chunks we got
    var chunks  = [];
    var err     = null;
    var timer   = null;

    // add any chunks we got
    proc.stdout.on('data', function(data) { 

      chunks.push(data);

    });

    // handle any errors we found
    proc.stderr.on('data', function(data) {

      // set as the error
      err = new Error(data);

    });

    // handle on close
    proc.on('close', function(code) {

      // clear the timeout
      if(timer) clearTimeout(timer);

      // done
      callback(err, Buffer.concat(chunks || []).toString());

    });

    // write to the stream
    proc.stdin.write(derFormat);
    proc.stdin.end();

    // timeout if any
    timer = setTimeout(function() {

      // done
      callback(new Error('Timeout'));

    }, 1000 * 5);

  };

  /**
  * Extracts known information from the PEM format of the certificate
  **/
  SSL.extractPEMVariables = function(pem, fn) {

    // get the details
    SSL.getPEMInformation(pem, function(err, parsedInfo) {

      // return the results returned from the PEM
      fn(null, {

        parent:     SSL.extractVariable(parsedInfo, /ca\s+issuer[s].*\-.*uri\:(.*)/gim),
        ocsp:       SSL.extractVariable(parsedInfo, /ocsp\s+\-\s+uri\:(.*)/gim),
        crl:        SSL.extractVariable(parsedInfo, /uri\:.*(http.*\.crl)/gim),
        signature:  SSL.extractVariable(parsedInfo, /Signature[\s+]Algorithm.*\:[\s+](.*)/gim),
        strengh:    SSL.extractVariable(parsedInfo, /Public\s+Key.*\:.*\((.*)\s+bit\)/gim)

      });

    });

  };

  /**
  * Parses the PEM and returns valid information
  **/
  SSL.readCertificateInfo = function(pemCertificate, fn) {

    // get the details from pem
    pem.readCertificateInfo(pemCertificate, function(err, info) {

      // check for a error
      if(err) {

        // report
        logger.error('Problem parsing details out of Pem Format', err);

        // done
        return fn(err);

      }

      // right so we got the info
      info = (info || {});

      // extract more variables
      SSL.extractPEMVariables(pemCertificate, function(err, meta) {

        // set our properties
        info = _.extend(info, meta);

        // done
        fn(null, info);

      });

    });

  };

  /**
  * Returns a root certificate that matches the issuer passed
  **/
  SSL.getRootCertificateByIssuer = function(issuer, fn) {

    // sanity checj
    if(!issuer) return fn(null);

    // get the certificates
    SSL.getInstalledRootCertificates(function(err, roots) {

      if(err) {

        return fn(err);

      }

      for(var i = 0; i < (roots || []).length; i++) {
        
        if(roots[i].commonName == issuer.commonName) {

          // done
          return fn(null, roots[i]);

        }

      }

      // done
      fn(null);

    });

  };


  /**
  * Extracts the installed certificates
  **/
  SSL.getInstalledRootCertificates = function(fn) {

    // return it
    if(global.PASSMARKED_ROOT_CERTS && 
        global.PASSMARKED_ROOT_CERTS.length > 0) {

      // done
      return fn(null, global.PASSMARKED_ROOT_CERTS);

    }

    // awk -v cmd='openssl x509 -noout -subject' ' /BEGIN/{close(cmd)};{print | cmd}' < /etc/ssl/certs/ca-certificates.crt
    // the singleton of the callback to call
    var callback = _.once(fn);

    // handle the delim
    var DELIM = '--------------------';

    // run the command
    childProcess.exec(
      "awk -v cmd='echo \"" + DELIM + "\";openssl x509' ' /BEGIN/{close(cmd)};{print | cmd}' < /etc/ssl/certs/ca-certificates.crt", 
      {

        maxBuffer: 1024 * 1024 * 100

      },
      function(err, stdout, stderr) {

      // clear the timeout
      if(timer) clearTimeout(timer);

      // get the lines
      var sections = (stdout || '').toString().split(DELIM);

      // the lines
      var subjects = [];

      async.eachLimit(sections || [], 10, function(pemCertificate, cb) {

        // read in the cert
        SSL.readCertificateInfo(pemCertificate, function(err, cert) {

          // sanity check
          if(!cert) return cb(null);

          // add it
          subjects.push(_.extend({}, cert, {

            pem: pemCertificate

          }));

          // output progress
          if(subjects.length % 15 == 0)
            logger.info('getInstalledRootCertificates', 'Loading certificates ' + subjects.length + '/' + sections.length);

          // done
          cb(null);
          
        });

      }, function(err) {

        // set the certs
        if(subjects.length > 0)
          global.PASSMARKED_ROOT_CERTS = subjects;

        // done
        callback(err, subjects);

      });

    });

    // timeout if any
    timer = setTimeout(function() {

      // done
      callback(new Error('Timeout'));

    }, 1000 * 15);

  };

  // return object instance
  return SSL;

};