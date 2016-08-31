SSL Renegotiation is making a new handshake while in the middle of a SSL/TLS connection. This is described in the standard, albeit not in very clear terms, especially when it comes to defining what guarantees renegotiation offer.

Renegotiation is very common when used with client certificates, being why it is recommended to enable to support a wide range of clients. There has been a issue reported in 2009 that allowed for a man-in-the-middle attack which was resolved using [RFC 5746](https://tools.ietf.org/html/rfc5746).

If your clients and server support "Secure Renegotiation" then things are fine for now (it prevents all currently known attacks). The whole concept of renegotiation and interleaved handshakes is still sorely in need of a more formal analysis and while this is still being used the recommendation is to enable SSL Renegotiation.

To securely enable renegotiation only server-side renegotiation must be accepted to prevent a DDOS attack on the SSL/TLS layer of your servers, meaning client-side renegotiation must be disabled.

# How do I fix this ?

Client-Side SSL Renegotiation should be disabled by default in most of the popular web servers. If not look at compiling a newer version of OpenSSL with your server to disable the the client-side renegotiations.

# Resources

* [Not clear on ssl renegotiation vulnerabilty](http://security.stackexchange.com/questions/24554/not-clear-on-ssl-renegotiation-vulnerabilty)
* [Transport Layer Security (TLS) Renegotiation Indication Extension](https://tools.ietf.org/html/rfc5746)
* [Security:Renegotiation](https://wiki.mozilla.org/Security:Renegotiation)
* [Briefing on TLS Renego](https://www.digicert.com/news/2011-06-03-ssl-renego.htm)
