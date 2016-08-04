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
const Utils           = require('./utils');

// keep track of root certificates
if(!global.PASSMARKED_ROOT_CERTS) global.PASSMARKED_ROOT_CERTS = [];

module.exports = exports = function(payload) {

  /**
  * Get our payload data
  **/
  var data = payload.getData();

  /**
  * Object to return
  **/
  var SSL = {};

  /**
  * Merge the libraries
  **/
  SSL = _.extend(SSL, Utils(payload));

  /** 
  * Cache of root certificates
  **/ 
  var roots = [];

  /**
  * Returns a presentable form of our internal certificate layout
  **/
  SSL.buildPresentableCertificate = function(cert) {

    // build the output
    var output = {

      pem:          cert.pem,
      source:       cert.collection,
      type:         cert.type,
      commonName:   cert.commonName,
      alt:          ((cert.san || {}).dns || []),
      title:        cert.commonName,
      description:  cert.commonName,
      index:        cert.index,
      verified:     cert.verified   === true,
      revoked:      cert.revoked    === true,
      signature:    cert.signature  || null,
      bits:         cert.strength   || null,
      crl:          cert.crl        || null,
      ocsp:         cert.ocsp       || null,
      url:          cert.url        || null

    };

    // returns the output
    return output;

  };

  /**
  * Builds the presentable chain
  **/
  SSL.buildPresentableChain = function(expectedPath, suppliedPath) {

    // the final chain to return 
    var chain               = [];

    // sort the chain
    var sortedChain = _.sortBy(expectedPath, 'index');

    // loop the expected certificate
    for(var i = 0; i < sortedChain.length; i++) {

      // use this as the certificate
      var cert = _.find(suppliedPath || [], function(item) {

        return item.commonName === sortedChain[i].commonName;

      });

      // did we find this cert ?
      if(cert) {

        // add our found certificate
        chain.push(SSL.buildPresentableCertificate(cert));

      } else {

        // add the certificate from the chain as it was not present
        chain.push(SSL.buildPresentableCertificate(sortedChain[i]));

      }

    }

    // returns the chain we generated
    return chain;

  };

  /**
  * Returns true if the given certificate fingerprint is present
  **/
  SSL.findByFingerprint = function(certificates, fingerprints, fn) {

    // create a slug we can use to check
    var slug    = _.pluck(fingerprints || {}, 'hash').join('-');

    // loop the certificates
    for(var i = 0; i < certificates.length; i++) {

      // loop the fingerprints
      for(var a = 0; a < (certificates[i].fingerprints || []).length; a++) {

        // check if any of the fingerprints match
        if(slug.indexOf(certificates[i].fingerprints[a].hash) !== -1) {

          // return the certificate
          return certificates[i];

        }

      }

    }

    // the default to return is null
    return null;

  };

  /**
  * Returns the possible SSL fingerprints
  **/
  SSL.getFingerPrintsFromPEM = function(cert, fn) {

    // list of hashes to add
    var fingerprints = [];

    // general all the fingerprints
    async.each([

      'md5', 'sha1', 'sha256'

    ], function (algorithm, cb) {

      // set the fingerprint
      pem.getFingerprint(cert, algorithm, function(err, prints) {

        // add to list
        if(prints && 
            S(prints.fingerprint || '').isEmpty() === false)
              fingerprints.push({

                algorithm:  algorithm,
                hash:       prints.fingerprint

              });

        // done
        cb(err);

      });

    }, function(err) {

      // finish
      fn(err, fingerprints);

    });

  };

  /**
  * Returns the timeout to use
  **/
  SSL.getTimeoutCommand = function() {

    // the path for timeout
    var platform          = os.platform();
    var timeoutCommand    = 'timeout';

    // fallback to gtimeout on osx
    if(platform === 'linux') {

      // set to gtimeout
      timeoutCommand = 'timeout ';

    } else if(platform === 'darwin') {

      // set to gtimeout
      timeoutCommand = '/usr/local/bin/gtimeout ';

    }

    // done
    return timeoutCommand;

  };

  /**
  * Returns the exec from bin
  **/
  SSL.getExecutable = function(version) {

    // return the full command
    return SSL.getTimeoutCommand() + ' 10 ' + SSL.getSSLExecutable(version);

  };

  /**
  * Execs the OPENSSL and first check the first testing stdout
  **/
  SSL.exec = function(cmd, fn) {

    // load out
    payload.debug('Running command: ' + cmd);

    // check if stdout and stderror was defined
    if(data.testingStdout || data.testingStderr) {

      // return the callback
      return fn(

        null, 
        (data.testingStdout || '').toString(), 
        (data.testingStderr || '').toString()

      );

    }

    // execute the actual process
    childProcess.exec(cmd, {}, function(err, stdout, stderr) {

      // check the error
      if(err) {

        // done
        return fn(err);

      }

      // to string just in case
      stdout = (stdout || '').toString();
      stderr = (stderr || '').toString();

      // done
      fn(err, stdout, stderr);

    });

  };

  /**
  * Returns all the certificates from the peer certificates
  **/
  SSL.getPeerCertificates = function(cert, fn) {

    // get the certificates
    var certs         = [];
    var cnames        = [];

    // the current item we are looking at
    var currentCertificate = cert;

    // keep count
    var count = 0;
    var run   = 0;

    // loop it
    while(currentCertificate !== null) {

      // check if not in list already
      if(cnames.indexOf(currentCertificate.subject.CN) === -1) {

        // add our mod
        cnames.push(currentCertificate.subject.CN);

        // add the certificate
        certs.push(_.extend({}, currentCertificate, {

          index: count

        }));

        // increment
        count++;

      }

      // internal run count
      run++;

      // update the current certificate
      currentCertificate = currentCertificate.issuerCertificate || null;

      // stop it
      if(currentCertificate && 
          (currentCertificate.issuer || {}).CN === currentCertificate.subject.CN) {

        // done
        break;

      }

      // break if more than 30, just in case this is a "forever" loop :\
      if(run > 30) break;

    }

    // done
    fn(null, certs);

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
        payload.error('Problem parsing details out of Pem Format', err);

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
  *
  **/
  SSL.verifyChain = function(certs, info, fn) {

    // create the chain
    var userCert      = certs[0];
    var middleCerts   = certs.slice(1, certs.length).join('\n');

    // get certificates by the same company
    fn(null);

  };

  /**
  * Downloads all the known certificate paths
  **/
  SSL.downloadPath = function(cert, index, fn) {

    // the list for the path
    var paths = [];

    // sanity check
    if(!cert) return fn(null, paths);

    // limit the stack if more than 20 already
    if(index > 20) return fn(null, paths);

    // check if this is a peer certificate
    if(index === 0) {

      // convert the certificate
      return SSL.convertDERtoPEM(cert.raw, function(err, pemCertificate) {

        // check for a error
        if(err) {

          // debug
          payload.error('Something went wrong while converting the DER to PEM', err);

          // done
          return fn(err, paths);

        }

        // get the finger prints of the passed certificates
        SSL.getFingerPrintsFromPEM(pemCertificate, function(err, prints) {

          // handle error
          if(err) {

            // output to stderr
            payload.error('Problem generating fingerprints of PEM file', err);

            // done
            return fn(err, paths);

          }

          // get the details from pem
          SSL.readCertificateInfo(pemCertificate, function(err, info) {

            // handle error
            if(err) {

              // output to stderr
              payload.error('Problem generating certificate info of PEM file', err);

              // done
              return fn(err, paths);

            }

            // add to list
            paths.push(_.extend({}, info, {

              pem:            pemCertificate,
              der:            cert.raw.toString('base64'),
              fingerprints:   prints,
              collection:     'supplied',
              index:          index,
              type:           'user'

            }));

            // trigger the next certificate walk
            SSL.downloadPath(info, index + 1, function(err, returnedPaths) {

              // find any other legacy roots
              SSL.verifyChain(_.pluck(returnedPaths, 'pem'), info, function() {

                // done
                fn(err, paths.concat(returnedPaths || []));

              });

            });

          });

        });

      });

    } else if(S(cert.parent || '').isEmpty() === false) {

      // downloads the certificate
      SSL.downloadCertificate(cert.parent, function(err, downloadedCert) {

        // check for a error
        if(err) {

          // output
          payload.error('Problem downloading the certificate from ' + path, err);

          // done
          return fn(err);

        }

        // convert the certificate
        SSL.convertDERtoPEM(downloadedCert, function(err, pemCertificate) {

          // check for a error
          if(err) {

            // debug
            payload.error('Something went wrong while converting the DER to PEM', err);

            // done
            return fn(err);

          }

          // get the finger prints of the passed certificates
          SSL.getFingerPrintsFromPEM(pemCertificate, function(err, prints) {

            // get the details from pem
            SSL.readCertificateInfo(pemCertificate, function(err, info) {

              // check for a error
              if(err) {

                // debug
                payload.error('Something went wrong checking the certificate info', err);

                // done
                return cb(err);

              }

              SSL.getRootCertificateByIssuer(info, function(err, rootCertificate) {

                // get the type
                var certType = 'user';
                if(info.commonName === ((info || {}).issuer || {}).commonName)
                  infoType = 'root';
                else
                  infoType = 'intermediate';

                // add to list
                paths.push(_.extend({}, info, {

                  url:            cert.parent,
                  pem:            pemCertificate.split('\n'),
                  der:            downloadedCert.toString('base64'),
                  fingerprints:   prints,
                  collection:     'expected',
                  index:          index,
                  type:           infoType

                }));

                // if not the root already ?
                // if(info.commonName == (info.issuer || {}).commonName) return fn(null, paths);

                // check the path
                if(S(info.parent || '').isEmpty() === true) {

                  SSL.walkTrustedChain(info.issuer || {}, index + 1, function(err, returnedPaths) {

                    // done
                    fn(err, paths.concat(returnedPaths || []));

                  });

                } else {

                  // trigger the next certificate walk
                  SSL.downloadPath(info, index + 1, function(err, returnedPaths) {

                    // done
                    fn(err, paths.concat(returnedPaths || []));

                  });

                }

              });

            });

          });

        });

      });

    } else {

      // done
      fn(null, paths);

    }

  };

  /**
  * Checks down the chain
  **/
  SSL.walkTrustedChain = function(info, index, fn) {

    // the list of paths to return
    var paths = [];

    // check if not over limit
    if(index > 20) {

      // stop at the limit, 20
      return fn(null, paths);

    }

    // return the info if not defined
    if(!info) {

      // finish returning the path
      return fn(null, paths);

    }

    // check if registed as a trusted certificate
    SSL.getRootCertificateByIssuer(info, function(err, cert) {

      // sanity check
      if(!cert) return fn(null, paths);

      // create fingerprints
      SSL.getFingerPrintsFromPEM(cert.pem, function(err, prints) {

        // get the type
        var certType = 'user';
        if(cert.index === 0)
          certType = 'user';
        else if(cert.commonName === ((cert || {}).issuer || {}).commonName)
          certType = 'root';
        else
          certType = 'intermediate';

        // add to list
        paths.push(_.extend({}, info, {

          pem:            cert.pem.split('\n'),
          der:            cert.der,
          fingerprints:   prints,
          collection:     'expected',
          index:          index,
          type:           certType

        }));

        // check if not the root
        if(cert.issuer && 
            cert.issuer.commonName !== cert.commonName) {

          // start to walk the actual tree
          return SSL.walkTrustedChain(cert.issuer, index + 1, function(err, returnedCert) {

            // return the paths
            fn(null, paths.concat(returnedCert || []));

          });

        }

        // return the paths
        fn(null, paths);

      });

    });

  };

  /**
  * Returns all the certificates from the peer certificates
  **/
  SSL.parseCertificates = function(peers, fn) {

    // get the certificates
    var certs         = [];

    // loop the certificates
    async.each(peers, function(cert, cb) {

      // do te request and get all the certificates
      SSL.convertDERtoPEM(cert.raw, function(err, pemCertificate) {

        // check for a error
        if(err) {

          // debug
          payload.error('Something went wrong while converting the DER to PEM', err);

          // done
          return cb(err);

        }

        // get the details from pem
        SSL.readCertificateInfo(pemCertificate, function(err, info) {

          // check for a error
          if(err) {

            // debug
            payload.error('Something went wrong checking the certificate info', err);

            // done
            return cb(err);

          }

          // create fingerprints
          SSL.getFingerPrintsFromPEM(pemCertificate, function(err, prints) {

            SSL.getRootCertificateByIssuer(info, function(err, rootCertificate) {

              // get the type
              var certType = 'user';
              if(cert.index === 0)
                certType = 'user';
              else if(rootCertificate && 
                  cert.commonName === ((cert || {}).issuer || {}).commonName)
                certType = 'root';
              else
                certType = 'intermediate';

              // add to list
              certs.push(_.extend({}, info, {

                pem:            pemCertificate.split('\n'),
                der:            cert.raw.toString('base64'),
                fingerprints:   prints,
                collection:     'supplied',
                index:          cert.index,
                type:           certType

              }));

              // done
              cb(null);

            });

          });

        });

      });

    }, function() {

      // done
      fn(null, certs);

    });

  };

  /**
  * Returns the CRT for the path given, but first check the cache
  **/
  SSL.downloadCertificate = function(path, fn) {

    // create the sha1 hash
    var shasum  = crypto.createHash('sha1');
    shasum.update(path);
    var hash    = shasum.digest('hex');

    // build the cache key
    var cacheKey = [

      'passmarked',
      'certificates',
      'der',
      hash

    ].join(':');

    // first check the cache for the certificate
    payload.get(cacheKey, function(err, cachedBody) {

      // did we get a error ?
      if(!err && cachedBody) {

        // return the cached version
        return fn(null, new Buffer(cachedBody, 'base64'));

      }

      // do the actual request and processing
      request({

        url:      path,
        timeout:  10 * 1000,
        encoding: null

      }, function(err, response, body) {

        // check if we have a error
        if(err) {

          // output to stderr
          payload.error('Problem downloading the given certificate from ' + path, err);

          // done
          return fn(err);

        }

        // check if we got the certificate
        if((response || {}).statusCode === 200) {

          // all good set in the cache and return
          return payload.set(cacheKey, body.toString('base64'), function(err) {

            // just output the error setting this in the cache
            if(err) payload.error('Problem settings the certificate from ' + path + ' in the cache', err);

            // just move on
            fn(null, body);

          });

        }

        // nope was not able to get the certificate
        fn(null);

      });

    });

  };

  // return object instance
  return SSL;

};