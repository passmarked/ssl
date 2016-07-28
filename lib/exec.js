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

module.exports = exports = function(payload, address, socket) {

  /**
  * Get our payload data
  **/
  var data = payload.getData();

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
      var cert = SSL.findByFingerprint(suppliedPath, sortedChain[i].fingerprints || {});

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
  * Returns a root certificate that matches the issuer passed
  **/
  SSL.getRootCertificateByIssuer = function(issuer, fn) {

    // get the certificates
    SSL.getInstalledRootCertificates(function(err, roots) {

      if(err) {

        return fn(err);

      }

      for(var i = 0; i < (roots || []).length; i++) {

        if(roots[i].commonName === issuer.commonName && 
            roots[i].organization === issuer.organization) {

          return fn(null, roots[i]);

        }

      }

      // done
      fn(null);

    });

  };

  /**
  * Returns all the parsed versions of the root certificates
  **/
  SSL.getInstalledRootCertificates = function(fn) {

    // check if not loaded yet ?
    if(global.PASSMARKED_ROOT_CERTS && 
        global.PASSMARKED_ROOT_CERTS.length > 0) {

      // just return, already loaded
      return fn(null, global.PASSMARKED_ROOT_CERTS || []);

    }

    // get the configured dirs
    var dirs = (process.env.PASSMARKED_CA_CERTS || '/etc/ssl/certs').split(',');

    // loop 
    async.eachLimit(dirs, 10, function(dir, cbb) {

      // load them in 
      fs.readdir(dir, function(err, files) {

        // loop all the files
        async.each(files, function(file, cb) {

          // read the file
          fs.readFile(path.join(dir, file), function(err, pemBody) {

            if(err) return cb(null);

            var pemCertificate = pemBody.toString();

            if(S(pemCertificate || '').isEmpty() === true) return cb(null);

            // get the finger prints of the passed certificates
            SSL.getFingerPrintsFromPEM(pemCertificate, function(err, prints) {

              // handle error
              if(err) {

                // output to stderr
                payload.error('Problem generating fingerprints of PEM file', err);

                // done
                return cb(null);

              }

              // get the details from pem
              SSL.readCertificateInfo(pemCertificate, function(err, info) {

                // handle error
                if(err) {

                  // output to stderr
                  payload.error('Problem generating certificate info of PEM file', err);

                  // done
                  return cb(null);

                }

                // right parse to pem
                global.PASSMARKED_ROOT_CERTS.push(_.extend({}, info, {

                  pem:            pemCertificate,
                  // der:            der.raw.toString('base64'),
                  fingerprints:   prints,
                  type:           'root'

                }));

                // done
                cb(null);

              });

            });

          });

        }, function() {

          // done with dir
          cbb(null);

        });

      });

    }, function() {

      console.log('loaded ' + global.PASSMARKED_ROOT_CERTS.length + ' certs');

      // done
      fn(null, global.PASSMARKED_ROOT_CERTS);

    });

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

    // loop it
    while(currentCertificate !== null) {

      // check if not in list already
      if(cnames.indexOf(currentCertificate.modulus) !== -1)
        break;

      // add our mod
      cnames.push(currentCertificate.modulus);

      // add the certificate
      certs.push(_.extend({}, currentCertificate, {

        index: count

      }));

      // increment
      count++;

      // update the current certificate
      currentCertificate = currentCertificate.issuerCertificate || null;

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
  * Downloads all the known certificate paths
  **/
  SSL.downloadPath = function(cert, index, fn) {

    // the list for the path
    var paths = [];

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

              // done
              fn(err, [].concat(paths, returnedPaths || []));

            });

          });

        });

      });

    }

    // so do we have a issuer ?
    if(S(cert.parent || '').isEmpty() === true) return fn(null, paths);

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

            // add to list
            paths.push(_.extend({}, info, {

              url:            cert.parent,
              pem:            pemCertificate,
              der:            downloadedCert.toString('base64'),
              fingerprints:   prints,
              collection:     'expected',
              index:          index,
              type:           info.commonName === (info.issuer || {}).commonName && info.organization === (info.issuer || {}).organization ? 'root' : 'intermediate'

            }));

            // trigger the next certificate walk
            SSL.downloadPath(info, index + 1, function(err, returnedPaths) {

              // done
              fn(err, [].concat(paths, returnedPaths || []));

            });

          });

        });

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

            // add to list
            certs.push(_.extend({}, info, {

              pem:            pemCertificate,
              der:            cert.raw.toString('base64'),
              fingerprints:   prints,
              collection:     'supplied',
              index:          cert.index,
              type:           cert.index === 0 ? 'user' : info.commonName === (info.issuer || {}).commonName && info.organization === (info.issuer || {}).organization ? 'root' : 'intermediate'

            }));

            // finish
            cb(null);

          });

        });

      });

    }, function() {

      // done
      fn(null, certs);

    });

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