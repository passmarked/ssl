var rulesToExport = require('./rules');
rulesToExport.bootstrap = function(logger, fn) {

  var utils   = require('./utils')(logger);
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
module.exports = exports = rulesToExport