// pull in our modules
const S     = require('string');
const url   = require('url');
const _     = require('underscore');

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, fn) {

  // get the data
  var data = payload.getData();

  // only if SSL
  if(S( (data.url || '').toLowerCase() ).startsWith("https") == false) {

    // debugging
    payload.debug('clientside', 'Skipping enabled as this is a HTTP page');

    // done
    return fn(null);

  }

  // check if we got any documents
  var clientSideDocuments = _.filter(data.documents || [], function(item) {

    return item.type == 'client';

  });

  // loop and add each
  for(var i = 0; i < (clientSideDocuments || []).length; i++) {

    // add the vunerable rule
    payload.addRule({

      type:         'critical',
      key:          'clientside',
      message:      'Using client-side redirect to HTTPS'

    }, {

      message:      '$ was redirected to $ using client-side $',
      identifiers:  [ data.url, clientSideDocuments[i].url, 'Javascript' ]

    });

  }

  // done !
  fn(null);

};