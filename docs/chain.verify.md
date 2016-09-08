The certificate provide was unable to be verified this could mean a few things (amongst others): 

* The certificate has expired 
* The certificate itself has been revoked
* The [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) that created the certificate is no longer trusted (happens more than you think)
* The server is missing a required intermediate certificate to valid the certificate

See [](https://wiki.mozilla.org/CA:IncludedCAs) for a list of [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) included in browsers like Firefox.

# How do I fix this ?

Verify that all certificates supplied in the chain are from a valid [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) by checking lists such as [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) by Mozilla.

Newer options include free certificates from [Let's Encrypt](https://letsencrypt.org/) which will provide a actual signed certificate that can be used for local/internal and public sites. 

Providers like [Cloudflare](https://www.cloudflare.com) have also started providing SSL certificates for any websites going through their proxy, making it easy to give any website HTTPS if there is no control over the actual web server.

# Resources

* [SSL Certificate framework 101: How does the browser actually verify the validity of a given server certificate?](http://security.stackexchange.com/questions/56389/ssl-certificate-framework-101-how-does-the-browser-actually-verify-the-validity)
* [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority)