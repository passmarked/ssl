The idea with TLS compression was to reduce the amount of data that needs to be sent from the server for the clients to initiate a authenticated session. In September 2012 the exploit CRIME (*Compression Ratio Info-leak Made Easy*) was introduced which allowed attackers to trick the browsers into trying multiple renegotiations keep track of the payload size on each. After a few requests attackers would be able to determine and extra full text headers from the authenticated session including cookies which allowed Session-Hijacking.

Although this is seen as a bigger client configuration than server, it is best practice to disable compression as newer browsers have disabled support for the protocol but older clients could still try to make use of the feature. Disabling removes any chance of a attacker using the attack on your users.

# How do I fix this ?

For shared hosting the web host must either be contacted to disable compression or making use of a provider like [Cloudflare](https://www.cloudflare.com) which will handle configuration of the feature.

For users who control their web server / config the following could be done according to their web server:

## NGINX

The CRIME attack uses SSL Compression, which is turned off by default in NGINX 1.1.6+/1.0.9+ (if OpenSSL 1.0.0+ is used) and nginx 1.3.2+/1.2.2+ (if any older versions of OpenSSL is used).

On older versions of NGINX or if your distro has not been backported the newest versions of OpenSSL, OpenSSL will need to be recompiled without ZLIB support. This will disable the use of OpenSSL using the DEFLATE compression method. If you do this then you can still use regular HTML DEFLATE compression.

## Apache

To disable SSL compression in Apache a feature flag can just be configured:

```SSLCompression off```

For more detailed information see [SSLCompression Directive](http://httpd.apache.org/docs/2.2/mod/mod_ssl.html#sslcompression) from [httpd.apache.org](http://httpd.apache.org/).

# Resources

* [CRIME](https://en.wikipedia.org/wiki/CRIME)
* [how to disable SSL/TLS compression](http://stackoverflow.com/questions/13880482/how-to-disable-ssl-tls-compression)
* [Strong SSL Security on nginx](https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html)
* [SSLCompression Directive](http://httpd.apache.org/docs/2.2/mod/mod_ssl.html#sslcompression)
