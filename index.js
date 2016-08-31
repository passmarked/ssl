const passmarked  = require('passmarked');
const _           = require('lodash');

/**
* Creates the actual test
**/
var Test = require('passmarked').createTest(

  {},
  require('./package.json'),
  require('./worker.json'),
  {

    rules: require('./lib/rules')

  }

);

/**
* Run when the worker is started
**/
Test.bootstrap = function(logger, fn) {

  var utils   = require('./lib/utils')(logger);
  logger.info('bootstrap', 'Loading Trusted Root Certificates into memory cache');
  utils.getInstalledRootCertificates(function(err, certs) {

    // check for a error
    if(err) return fn(err);

    // debug
    logger.info('bootstrap', 'Loaded ' + certs.length + ' Trusted Root Certificates');

    // all done
    fn(err);

  });

};

/**
* Expose the test
**/
module.exports = exports = Test