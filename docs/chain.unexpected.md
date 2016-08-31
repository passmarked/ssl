[Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority)'s often issue [Intermediate certificates](https://en.wikipedia.org/wiki/Intermediate_Certificate_Authority) that are used to sign and create new certificates.

On clients that allow connections over HTTPS a list of root are included which are checked for a valid certificate, see [root certificates included by Mozilla](https://wiki.mozilla.org/CA:IncludedCAs) for example. 

These lists often do not include the intermediate certificate and can vary depending on provider/browser and device. It is advised to build a full chain all the way up to the root, but excluding the root itself. This allows all devices, even if they do not have the intermediate certificate, to view the site as verified over https.

The chain presented by this domain included a certificate that was not expected to be seen in the certificate chain which might cause unexpected behaviour users on mobile devices especially.

# How do I fix this ?

Verify that all certificates supplied in the chain are part of the expected list with all the intermediates and server certificate with nothing else present.

Newer options include free certificates from [Let's Encrypt](https://letsencrypt.org/) which will provide a actual signed certificate that can be used for local/internal and public sites.  Which takes the management out of the server admin's hands to fix these problems.

Providers like [Cloudflare](https://www.cloudflare.com) have also started providing SSL certificates for any websites going through their proxy, making it easy to give any website HTTPS if there is no control over the actual web server.

# Resources

* [SSL Certificate framework 101: How does the browser actually verify the validity of a given server certificate?](http://security.stackexchange.com/questions/56389/ssl-certificate-framework-101-how-does-the-browser-actually-verify-the-validity)
* [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority)