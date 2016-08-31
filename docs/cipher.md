As the waves of time continue and more exploits are found in older technology, so must we constantly review cipher suites used by our servers. 

Older and weaker ciphers put servers at risk of explotation and must be disabled. The following ciphers are considered bad and must be disabled:

* NULL
* EXPORT
* LOW
* 3DES

# How do I fix this ?

Configure your web server to disable these protocols (normally by negating them in the server), to get started here is a recommended list of ciphers supporting older clients till XP:

```EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4```

Take note of the negated ciphers:

* `!aNULL`
* `!eNULL`
* `!EXPORT`
* `!DES`
* `!MD5`
* `!PSK`
* `!RC4`

These are considered bad, and not matter which list of ciphers the server ends up using those must not be enabled.

# Resources

* [Security/Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)
* [Identify and disable weak cipher suites](http://security.stackexchange.com/questions/48325/identify-and-disable-weak-cipher-suites)
* [How to Disable SSL 2.0 and SSL 3.0 in IIS 7](https://www.sslshopper.com/article-how-to-disable-ssl-2.0-in-iis-7.html)
* [Strong SSL Security on nginx](https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html)
