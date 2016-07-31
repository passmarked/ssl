/**
* Handles checking for missing certificates in our chain
**/
module.exports = exports = function(payload, params, fn) {

  // local params
  var expectedCerts       = params.expected;
  var suppliedCerts       = params.supplied;
  var presentableCerts    = params.merged;
  var address             = params.address;

  // the presentable cards
  var fullCertChain       = [];

  // loop the certificates
  for(var i = 0; i < suppliedCerts.length; i++) {

    // the other certificate
    var cert = null;

    // get if the index matches on expected
    for(var a = 0; a < expectedCerts.length; a++) {

      // find the certificate
      if(suppliedCerts[i].commonName === expectedCerts[a].commonName) {

        // set the certificate
        cert = expectedCerts[a];

      }

    }

    // check the order if found
    if(cert) {

      console.log(cert.commonName + ' === ' + suppliedCerts[i].commonName);
      console.log(cert.index + ' === ' + suppliedCerts[i].index);

      // check it
      if(cert.index != suppliedCerts[i].index) {

        // add the order rule
        payload.addRule({

          key:          'chain.order',
          message:      'Invalid order to certificate chain',
          type:         'error'

        }, {

          display:      'chain',
          chain:        presentableCerts,
          message:      'Certificate from $ was expected at position $ but found at $',
          identifiers:  [ suppliedCerts[i].commonName, cert.index, suppliedCerts[i].index ]

        })

      }

    } else if(suppliedCerts[i].type != 'root') {

      // add the rule
      payload.addRule({

        key:          'chain.unexpected',
        message:      'Unexpected certificate supplied in chain',
        type:         'error'

      }, {

        display:      'chain',
        chain:        presentableCerts,
        message:      'Unexpected certificate from $ supplied for $',
        identifiers:  [ suppliedCerts[i].commonName, address ]

      })

    }

  }

  // finish
  fn(null);

};