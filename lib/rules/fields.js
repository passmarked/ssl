// pull in our modules
const S               = require('string');
const url             = require('url');
const cheerio         = require('cheerio');

/**
* Regex for Chrome's regex:
* https://chromium.googlesource.com/chromium/chromium/+/master/chrome/browser/autofill/autofill_regex_constants.cc.utf8#122
**/
const CARD_PATTERNS = [
  
  "card.?holder|name.*\\bon\\b.*card|cc.?name|cc.?full.?name|owner",
  "karteninhaber",  // de-DE
  "nombre.*tarjeta", // es
  "nom.*carte", // fr-FR
  "nome.*cart", // it-IT
  "名前", // ja-JP
  "Имя.*карты", // ru
  "信用卡开户名|开户名|持卡人姓名", // zh-CN
  "持卡人姓名", // zh-TW

  "card.?number|card.?#|card.?no|cc.?num|acct.?num",
  "nummer", // de-DE
  "credito|numero|número", // es
  "numéro", // fr-FR
  "カード番号", // ja-JP
  "Номер.*карты", // ru
  "信用卡号|信用卡号码", // zh-CN
  "信用卡卡號", // zh-TW
  "카드",  // ko-KR

  "verification|card identification|security code|cvn|cvv|cvc|csc"

];

/**
* Pulls the certificate and checks ge
**/
module.exports = exports = function(payload, fn) {

  // get the data
  var data = payload.getData();

  // only if SSL
  if(S( (data.url || '').toLowerCase() ).startsWith("https") == true) {

    // debugging
    payload.debug('enabled', 'Skipping fields check as HTTPS is done');

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

    // flag if we found credit cards on this page
    var creditCardFlag  = false;
    var passwordFlag    = false;

    // loop the fields on the page
    $('body > input').each(function(index, elem) {

      // get the type of the input
      var fieldType     = $(elem).attr('type') || '';
      var fieldName     = S($(elem).attr('name') || '').truncate(255).s;

      // check if we found the type
      if(S(fieldType || '').isEmpty() === true) {

        // debug
        payload.debug('fields', fieldType + ' was blank');

        // done
        return;

      }

      // check if password and protocol HTTPS
      if(fieldType == 'text' && 
          (uri.protocol || '').indexOf('http:') === 0 && 
            creditCardFlag == false) {

        // loop the patterns
        for(var i = 0; i < CARD_PATTERNS.length; i++) {

          // check if this has anything to do with credit card information
          if(fieldName.match(CARD_PATTERNS[i]) !== null) {

            // debug
            payload.debug('fields', CARD_PATTERNS[i] + ' matched for the name: ' + fieldName);

            // build a code snippet
            var build = payload.getSnippetManager().build(lines, lastLine, function(line) {

              return line.toLowerCase().indexOf('<input') !== -1 && 
                        line.toLowerCase().indexOf('type="' + fieldType) !== -1;

            });

            // check if we got it
            if(build) {

              // set the subject
              lastLine = build.subject;

              // set as flagged
              creditCardFlag = true;

              // add the rule
              payload.addRule({

                type:         'critical',
                key:          'fields.creditcard',
                message:      'Page will be marked as unsecure because of credit card input'

              }, {

                message:      '<input name="$"',
                identifiers:  [ fieldName.toString() ],
                display:      'code',
                code:         build

              });

            }

            // break it
            break;

          }

        }

      }

      // check if password and protocol HTTPS
      if(fieldType == 'password' && 
          (uri.protocol || '').indexOf('http:') === 0 && 
            passwordFlag == false) {

        // build a code snippet
        var build = payload.getSnippetManager().build(lines, lastLine, function(line) {

          return line.toLowerCase().indexOf('<input') !== -1 && 
                    line.toLowerCase().indexOf('type="' + fieldType) !== -1;

        });

        // check if we got it
        if(build) {

          // set the subject
          lastLine = build.subject;

          // set as flagged
          passwordFlag = true;

          // add the rule
          payload.addRule({

            type:         'critical',
            key:          'fields.password',
            message:      'Page will be marked as unsecure because of password input'

          }, {

            message:      '<input name="$"',
            identifiers:  [ uri.hostname ],
            display:      'code',
            code:         build

          });

        }

      }

    });

    // done !
    fn(null);

  });

};