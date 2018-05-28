The URL given presents as HTTPS but the connection attempt to the server over TLS failed. 

This likely points to a network error either on the way to the server or on the server itself.

Another possible issue here might be a cipher mismatch between what our TLS/SSL client accepts and what your server is giving out. See below for our list of configured ciphers.

# How do I fix this ?

Contact your service provider to check for any maintenance or unexpected issues, status pages from various providers also provide a good overview:

* [Google Cloud](https://status.cloud.google.com/)
* [DigitalOcean](https://status.digitalocean.com/)
* [Rackspace Status Page](https://status.rackspace.com/)
* [AWS (Amazon)](http://status.aws.amazon.com/)

The Passmarked client has the following servers configured that are expected:

* `ECDHE-RSA-AES256-SHA`
* `ECDHE-ECDSA-AES256-SHA`
* `SRP-DSS-AES-256-CBC-SHA`
* `SRP-RSA-AES-256-CBC-SHA`
* `SRP-AES-256-CBC-SHA`
* `DHE-RSA-AES256-SHA`
* `DHE-DSS-AES256-SHA`
* `DHE-RSA-CAMELLIA256-SHA`
* `DHE-DSS-CAMELLIA256-SHA`
* `AECDH-AES256-SHA`
* `ADH-AES256-SHA`
* `ADH-CAMELLIA256-SHA`
* `ECDH-RSA-AES256-SHA`
* `ECDH-ECDSA-AES256-SHA`
* `AES256-SHA`
* `CAMELLIA256-SHA`
* `PSK-AES256-CBC-SHA`
* `ECDHE-RSA-DES-CBC3-SHA`
* `ECDHE-ECDSA-DES-CBC3-SHA`
* `SRP-DSS-3DES-EDE-CBC-SHA`
* `SRP-RSA-3DES-EDE-CBC-SHA`
* `SRP-3DES-EDE-CBC-SHA`
* `EDH-RSA-DES-CBC3-SHA`
* `EDH-DSS-DES-CBC3-SHA`
* `AECDH-DES-CBC3-SHA`
* `ADH-DES-CBC3-SHA`
* `ECDH-RSA-DES-CBC3-SHA`
* `ECDH-ECDSA-DES-CBC3-SHA`
* `DES-CBC3-SHA`
* `PSK-3DES-EDE-CBC-SHA`
* `ECDHE-RSA-AES128-SHA`
* `ECDHE-ECDSA-AES128-SHA`
* `SRP-DSS-AES-128-CBC-SHA`
* `SRP-RSA-AES-128-CBC-SHA`
* `SRP-AES-128-CBC-SHA`
* `DHE-RSA-AES128-SHA`
* `DHE-DSS-AES128-SHA`
* `DHE-RSA-SEED-SHA`
* `DHE-DSS-SEED-SHA`
* `DHE-RSA-CAMELLIA128-SHA`
* `DHE-DSS-CAMELLIA128-SHA`
* `AECDH-AES128-SHA`
* `ADH-AES128-SHA`
* `ADH-SEED-SHA`
* `ADH-CAMELLIA128-SHA`
* `ECDH-RSA-AES128-SHA`
* `ECDH-ECDSA-AES128-SHA`
* `AES128-SHA`
* `SEED-SHA`
* `CAMELLIA128-SHA`
* `PSK-AES128-CBC-SHA`
* `ECDHE-RSA-RC4-SHA`
* `ECDHE-ECDSA-RC4-SHA`
* `AECDH-RC4-SHA`
* `ADH-RC4-MD5`
* `ECDH-RSA-RC4-SHA`
* `ECDH-ECDSA-RC4-SHA`
* `RC4-SHA`
* `RC4-MD5`
* `PSK-RC4-SHA`
* `EDH-RSA-DES-CBC-SHA`
* `EDH-DSS-DES-CBC-SHA`
* `ADH-DES-CBC-SHA`
* `DES-CBC-SHA`
* `EXP-EDH-RSA-DES-CBC-SHA`
* `EXP-EDH-DSS-DES-CBC-SHA`
* `EXP-ADH-DES-CBC-SHA`
* `EXP-DES-CBC-SHA`
* `EXP-RC2-CBC-MD5`
* `EXP-ADH-RC4-MD5`
* `EXP-RC4-MD5`
* `ECDHE-RSA-NULL-SHA`
* `ECDHE-ECDSA-NULL-SHA`
* `AECDH-NULL-SHA`
* `ECDH-RSA-NULL-SHA`
* `ECDH-ECDSA-NULL-SHA`
* `NULL-SHA`
* `NULL-MD5`

# Resources

* [Google Cloud](https://status.cloud.google.com/)
* [DigitalOcean](https://status.digitalocean.com/)
* [Rackspace Status Page](https://status.rackspace.com/)
* [AWS (Amazon)](http://status.aws.amazon.com/)