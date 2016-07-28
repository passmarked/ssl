# @passmarked/ssl 

![NPM](https://img.shields.io/npm/dt/@passmarked/ssl.svg) [![Build Status](https://travis-ci.org/passmarked/ssl.svg)](https://travis-ci.org/passmarked/ssl)

[Passmarked](http://passmarked.com?source=github&report=ssl) is a suite of tests that can be run against any page/website to identify issues with parity to most online tools in one package.

The [Terminal Client](http://npmjs.org/package/passmarked) is intended for use by developers to integrate into their workflow/CI servers but also integrate into their own application that might need to test websites and provide realtime feedback.

All of the checks on [Passmarked](http://passmarked.com?source=github&report=ssl) can be voted on importance and are [open-sourced](http://github.com/passmarked/suite), to encourage community involvement in fixing and adding new rules. We are building the living Web Standard and love any [contributions](#contributing).

## Synopsis

The module firstly does a resolve on the DNS address (or just directly uses the single IP), and then runs the following tests again each of the resolved IP's:

The rules checked in this module are:

* **anonymous** - Server has ciphers ciphers enabled
* **cipher** - Server has a known weak cipher enabled, any of the following ciphers will raise this issue: **NULL**, **EXPORT**, **LOW**, **3DES**, **MD5**, **RSK** or **RC4**
* **compression** - Server has TLS compression enabled which also leads to a vulnerability for the OpenSSL [CRIME](https://en.wikipedia.org/wiki/CRIME) attack
* **expire** - The certificate is shorter than a month away from expiring.
* **expired** - The certificate presented by the server has expired and is not valid anymore
* **freak** - The server has the **EXPORT** cipher enabled which leads to a vulnerability for the [FREAK](https://freakattack.com/) attack.
* **heartbleed** - Vulnerability to the [HeartBleed](http://heartbleed.com/) attack was found
* **host** - The certificate presented by the server did not have the host requested featured, leading to a hostname mismatch error.
* **missing** - The server did not supply a certificate, this normally indicates that no certificate was configured although SSL is being offered.
* **poodle** - Vulnerability to the [POODLE](https://en.wikipedia.org/wiki/POODLE) attack was found
* **https.enabled** - If the given url is not HTTPS, the issue is raised to recommend switching to SSL for the security of useres.
* **renegotiation.client** - Client Renegotiation is enabled but was expecting it to be disabled to lock the server down correctly.
* **sha1** - The returned certificate makes use of SHA1 hashing which is obsolete after 2016, browsers will be giving out warnings from October 2016 about these certificates that are signed with SHA1.
* **ssl2** - SSLv2 was detected on the server, this should be disabled as fast as possible.
* **ssl3** - SSLv3 was detected on the server, this should be disabled as fast as possible.
* **sni** - SNI is not enabled, meaning the server can only serve a single website.
* **oscp** - [OSCP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) was not detected.
* **oscp.cert** - The [OSCP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) certificate status returned by the server was not successfull.
* **tls1** - TLSv1 was not detected, should be enabled to ensure compatibility with the largest secured user base.
* **tls1.1** - TLSv1.1 was not detected, should be enabled to ensure compatibility with the largest secured user base.
* **tls1.2** - TLSv1.2 was not detected, should be enabled to ensure compatibility with the largest secured user base.
* **verify** - Verification of the certificate with common known root certificated failed, most probably could indicate a privately signed key.
* **chain.missing** - Missing intermediate certificates detected from the chain returned by the server, the daa returned contains the full chain as expected with all the needed certificates.
* **chain.weak** - Certificates that were expected in the chain contains certificates using a weaker signature hash.
* **chain.root** - The certificate chain returned from the server contains a root certificate, which is according to how PKI is designed will be wasting a few bytes for every request. These should be removed.
* **chain.order** - Order of the certifiate chain provided is wrong
* **chain.verify** - Unable to verify a intermediate certificate or if any of the certificates have been revoked.
* **chain.unexpected** - Unable to verify a intermediate certificate or if any of the certificates have been revoked.
* **android** - The configured settings on the server might cause problems for Android devices connecting to the server over HTTPS.
* **ios** - The configured settings on the server might cause problems for IOS devices connecting to the server over HTTPS.
* **windows** - The configured settings on the server might cause problems for Windows devices connecting to the server over HTTPS.
* **linux** - The configured settings on the server might cause problems for Linux devices connecting to the server over HTTPS.
* **macos** - The configured settings on the server might cause problems for MacOS devices connecting to the server over HTTPS.
* **opera** - The configured settings on the server might cause problems for Opera devices connecting to the server over HTTPS.
* **blackberry** - The configured settings on the server might cause problems for Opera devices connecting to the server over HTTPS.

## Running

The rules are checked everytime a url is run through Passmarked or our API. To run using the hosted system head to [passmarked.com](http://passmarked.com?source=github&report=ssl) or our [Terminal Client](http://npmjs.org/package/passmarked) use:

```bash
npm install -g passmarked
passmarked --filter=ssl example.com
```

The hosted version allows free runs from our homepage and the option to register a site to check in its entirety.
Using the Passmarked npm module (or directly via the API) integrations are also possible to get running reports with all the rules in a matter of seconds.

## Running Locally

All rules can be run locally using our main integration library. This requires installing the package and any dependencies that the code might have such as a specific version of OpenSSL, see [#dependencies](#dependencies)

First ensure `passmarked` is installed:

```bash
npm install passmarked
npm install @passmarked/ssl
```

After which the rules will be runnable using promises:

```javascript
passmarked.createRunner(
  require('@passmarked/ssl'), // this package
  require('@passmarked/ssl') // to test SSL
).run({
  url: 'http://example.com',
  body: 'body of page here',
  har: {log: {entries: []}}
}).then(function(payload) {
  if (payload.hasRule('secure')) {
    console.log('better check that ...');
  }
  var rules = payload.getRules();
  for (var rule in rules) {
    console.log('*', rules[rule].getMessage());
  }
}).catch(console.error.bind(console));
```

Alternatively, callbacks are also available:

```javascript
passmarked.createRunner(
  require('@passmarked/ssl'),
  require('@passmarked/ssl'),
  require('@passmarked/inspect')
).run({
  url: 'http://example.com',
  body: 'body of page here',
  har: {log: {entries: []}}
}, function(err, payload) {
  if (payload.hasRule('secure')) {
    console.log("better check that ...");
  }
  var rules = payload.getRules();
  for (var rule in rules) {
    console.log('*', rules[rule].getMessage());
  }
});
```

## Dependencies

The module expects a updated version of OpenSSL, at the time of writing `openssl-1.0.2h`. The module expects the newest compiled excutable to present at `/usr/local/ssl/bin/openssl`.


```bash
# install our essentials to build openssl
apt-get install -y build-essential

# upgrade to a much newer and specific version of ssl
wget -O /tmp/openssl-1.0.2h.tar.gz https://www.openssl.org/source/openssl-1.0.2h.tar.gz
cd /tmp/ && tar -xf /tmp/openssl-1.0.2h.tar.gz
rm /tmp/openssl-1.0.2h.tar.gz
cd /tmp/openssl-1.0.2h && ./config
cd /tmp/openssl-1.0.2h && make depend
cd /tmp/openssl-1.0.2h && make
cd /tmp/openssl-1.0.2h && make install
rm -R /tmp/openssl-1.0.2h
```

We do also host a binary build for x86 Ubuntu over at [package.passmarked.com/openssl/builds/openssl-x86-1.0.2h.bin](https://package.passmarked.com/openssl/builds/openssl-x86-1.0.2h.bin) that is mostly used for quick testing but would work if you require a quick way to get started.

The module also expects to see `timeout` from `coreutils` present in some form, this defaults to `gtimeout` on MacOS which can be installed using:

```
brew install coreutils
```

Also be sure to install the CA certificates and keep it updated, as these are used to check if a certificate is valid:

```bash
apt-get install -y ca-certificates
```

## Rules

Rules represent checks that occur in this module, all of these rules have a **UID** which can be used to check for specific rules. For the structure and more details see the [Wiki](https://github.com/passmarked/passmarked/wiki) page on [Rules](https://github.com/passmarked/passmarked/wiki/Create).

> Rules also include a `type` which could be `critical`, `error`, `warning` or `notice` giving a better view on the importance of the rule.

## Contributing

```bash
git clone git@github.com:passmarked/ssl.git
npm install
npm test
```

Pull requests have a prerequisite of passing tests. If your contribution is accepted, it will be merged into `develop` (and then `master` after staging tests by the team) which will then be deployed live to [passmarked.com](http://passmarked.com?source=github&report=ssl) and on NPM for everyone to download and test.

## About

To learn more visit:

* [Passmarked](http://passmarked.com)
* [Terminal Client](https://www.npmjs.com/package/passmarked)
* [NPM Package](https://www.npmjs.com/package/@passmarked/ssl)
* [Slack](http://passmarked.com/chat?source=github&report=ssl) - We have a Slack team with all our team and open to anyone using the site to chat and figure out problems. To join head over to [passmarked.com/chat](http://passmarked.com/chat?source=github&report=ssl) and request a invite.

## License

Copyright 2016 Passmarked Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
