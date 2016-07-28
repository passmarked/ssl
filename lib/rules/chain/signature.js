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
    if((presentableCerts[i].signature || '').toLowerCase().indexOf('sha1with') === 0) {

      // add the rule
      payload.addRule({

        key:          'chain.weak',
        message:      'Weak signature detected on certificates in chain',
        type:         presentableCerts[i].index === 0 ? 'error' : 'notice'

      }, {

        display:      'chain',
        chain:        presentableCerts,
        message:      'Certificate supplied by $ from $ is using $ which is being phased out Dec 2016',
        identifiers:  [ address, presentableCerts[i].commonName, 'sha1' ]

      });

    }

  }

  // finish
  fn(null);

};