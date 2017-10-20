// pull in our modules
const S               = require('string');
const url             = require('url');
const cheerio         = require('cheerio');

/**
* Checks if the any form submission on the page goes to http from https,
* this will cause browsers to show a security alert to the user. 
**/
module.exports = exports = function(payload, fn) {

  // get the data
  var data = payload.getData();

  // only if SSL
  if(S( (data.url || '').toLowerCase() ).startsWith("https") == false) {

    // debugging
    payload.debug('fields', 'Skipping fields check as HTTPS is enabled for request');

    // done
    return fn(null);

  }

  // get the content
  payload.getPageContent(function(err, content) {

    // check for a error
    if(err) {

      // output the error
      payload.error('fields', 'Problem getting the page content', err);

      // done
      return fn(err);

    }

    // check if the content is not empty
    if(S(content || '').isEmpty() === true) {

      // debug
      payload.warning('fields', 'The content given was empty or blank');

      // done
      return fn(null);

    }

    // parse the url
    var uri = url.parse(data.url);

    // load the content
    var $ = cheerio.load(content || '');

    // get the lines of the file
    var lines = content.split('\n');

    // the last line for the code search
    var lastLine = -1;

    // loop the fields on the page
    $('body form').each(function(index, elem) {

      // get the type of the input
      var formAction      = $(elem).attr('action') || '';

      // ignore blank
      if(S(formAction).isEmpty() === true || 
          S(formAction).trim().s.indexOf('#') === 0 ||
            S(formAction).trim().s.indexOf('javascript:void') === 0 ||
              S(formAction).trim().s.indexOf('//') === 0 || 
                S(formAction).trim().s.indexOf('/') === 0 || 
                  S(formAction).trim().s.indexOf('https://') === 0) {

        // all good, just skip
        return;

      }

      // build a code snippet
      var build = payload.getSnippetManager().build(lines, lastLine, function(line) {

        return line.toLowerCase().indexOf('action="' + formAction.slice(0, 10)) !== -1;

      });

      // parse the link
      var actionUri = url.parse(formAction);

      // sanity check
      if(!build) return;

      // set the subject
      lastLine = build.subject;

      // build out the occurrence details
      var occurrence = {

        message:      '<form action="$"',
        identifiers:  [ formAction ],
        display:      'code',
        code:         build

      };

      // check if local
      var isLocal = S(actionUri.hostname || '').endsWith((uri.hostname || '').replace('www.', ''));

      // is this local
      if(isLocal == true) {

        // yeap, this is quite bad ...
        payload.addRule({

          type:         'critical',
          key:          'form.internal',
          message:      'Form submissions to non-secure (http) pages will result in a security warning to users'

        }, occurrence);

      } else {

        // note worthy
        payload.addRule({

          type:         'warning',
          key:          'form.external',
          message:      'Form submissions to external non-secure (http) pages will result in a security warning to users'

        }, occurrence);

      }

    });

    // done !
    fn(null);

  });

};