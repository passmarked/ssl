/**
* Handles checking for missing certificates in our chain
**/
module.exports = exports = function(payload, params, fn) {

  // local params
  var expectedCerts       = params.expected;
  var suppliedCerts       = params.supplied;
  var presentableCerts    = params.merged;
  var address             = params.address;

  // loop the certs we have and report any we might be missing
  for(var i = 0; i < presentableCerts.length; i++) {

    // check the collection
    if(presentableCerts[i].source == 'expected') {

      // add the rule
      payload.addRule({

        key:          'chain.missing',
        message:      'Missing intermediate certificates',
        type:         'critical'

      }, {

        display:      'chain',
        chain:        presentableCerts,
        message:      'Intermediate certificate from $ not found for $',
        identifiers:  [ presentableCerts[i].commonName, address ]

      });

    }

  }

  // finish
  fn(null);

};