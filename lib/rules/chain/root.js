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
    if(presentableCerts[i].type == 'root') {

      // add the rule
      payload.addRule({

        key:          'chain.root',
        message:      'Root certificate should not be returned in chain',
        type:         'notice'

      }, {

        display:      'chain',
        chain:        presentableCerts,
        message:      'Root certificate from $ on address $ can be removed to save some bandwidth',
        identifiers:  [ presentableCerts[i].commonName, address ]

      });

    }

  }

  // finish
  fn(null);

};