/**
* Handles checking for missing certificates in our chain
**/
module.exports = exports = function(payload, params, fn) {

  // local params
  var expectedCerts       = params.expected;
  var suppliedCerts       = params.supplied;
  var presentableCerts    = params.merged;
  var address             = params.address;

  // pull out the params we can use
  var client              = params.client;

  // loop the certs we have and report any we might be missing
  for(var i = 0; i < presentableCerts.length; i++) {

    // check the collection
    if((presentableCerts[i].signature || '').toLowerCase().indexOf('sha1with') === 0) {

      // depending on the type
      if(presentableCerts[i].type == 'user') {

        // add the rule
        payload.addRule({

          key:          'signature',
          message:      'Weak signature detected on server certificate',
          type:         'error',

        }, {

          display:      'chain',
          chain:        presentableCerts,
          message:      'Server certificate supplied by $, $ is using $ which is being phased out Dec 2016',
          identifiers:  [ address, presentableCerts[i].commonName, 'sha1' ]

        });

      } else if(presentableCerts[i].type != 'root') {

        // add the rule
        payload.addRule({

          key:          'chain.signature',
          message:      'Weak signature detected on certificates in chain',
          type:         'notice'

        }, {

          display:      'chain',
          chain:        presentableCerts,
          message:      'Certificate supplied by $, $ is using $ which is being phased out Dec 2016',
          identifiers:  [ address, presentableCerts[i].commonName, 'sha1' ]

        });

      }

    }

  }

  // finish
  fn(null);

};