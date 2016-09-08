[FREAK](https://en.wikipedia.org/wiki/Freak) (*Factoring RSA-EXPORT Keys*) is a Man-in-the-middle vulnerability discovered by a group of cryptographers  at [INRIA, Microsoft Research and IMDEA](https://www.smacktls.com/). 

The vulnerability dates back to the 1990s, when the US government banned selling crypto software overseas, unless it used export cipher suites which involved encryption keys no longer than 512-bits.

The attack usses the fact that some modern browser clients had (and have on older version) a bug in them, where the bug caused the browser to accept export-grade RSA even if they did not request or broadcasted support. Allowing attackers to downgrade the level of security on a connection provided that the client is vulnerable and the server supports export RSA.

# How do I fix this ?

Upgrade OPENSSL on the server along with negating the *EXPORT* cipher suite, a starting point for a list of safe ciphers would be:

```EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4
```

Take note of the `!EXPORT` keyword, disabling export-grade RSA.

# Resources

* [FREAK - Wikipedia](https://en.wikipedia.org/wiki/Freak)
* [INRIA, Microsoft Research and IMDEA](https://www.smacktls.com/)
* [Strong SSL Security on nginx](https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html#Factoring_RSA-EXPORT_Keys_(FREAK))
* [Mozilla SSL Configuration Generator](https://mozilla.github.io/server-side-tls/ssl-config-generator)
* [Microsoft Schannel](https://technet.microsoft.com/en-us/library/security/3046015)
* [CVE-2015-0204](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0204)
* [FREAK](https://en.wikipedia.org/wiki/FREAK)
* [Export of cryptography from the United States](https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States)
* [Freak Attack](https://freakattack.com)
