The SSL certificate for your domain is too weak for transmission of sensitive data. Certificates with a strength lower than 256 bits are more vulnerable to malicious third-parties impersonating your web-application server.

# How do I fix this?

Purchase (or use a free service like Let's Encrypt) a new SSL certificate with a higher bit-strength.

# Resources

* [Let's Encrypt](https://letsencrypt.org)
* [Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)
* [StackExchange: How is it possible that people observing an HTTPS connection being established wouldn't know how to decrypt it?](http://security.stackexchange.com/questions/6290/how-is-it-possible-that-people-observing-an-https-connection-being-established-w/6296#6296)
* [StackExchange: Understanding 2048-bit SSL and 256-bit encryption](http://security.stackexchange.com/questions/19473/understanding-2048-bit-ssl-and-256-bit-encryption)
