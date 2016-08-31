[Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority)'s often issue [Intermediate certificates](https://en.wikipedia.org/wiki/Intermediate_Certificate_Authority) that are used to sign and create new certificates.

On clients that allow connections over HTTPS a list of root are included which are checked for a valid certificate, see [root certificates included by Mozilla](https://wiki.mozilla.org/CA:IncludedCAs) for example. 

These lists often do not include the intermediate certificate and can vary depending on provider/browser and device. It is advised to build a full chain all the way up to the root, but excluding the root itself. This allows all devices, even if they do not have the intermediate certificate, to view the site as verified over https.

The SHA1 signature was used for quite a while to sign certificates, but the signature has proven to be insecure with the advent of faster processors. The signature is being phased out and will start giving warnings to users when a certificate is found using the signature after Dec 2016.

# How do I fix this ?

Verify that all certificates supplied in the chain (excluding the root) are not signed using a SHA1 signature. If they are, either request a renwenal of the servers' certificate or any [Intermediate certificates](https://en.wikipedia.org/wiki/Intermediate_Certificate_Authority) found to be signed using SHA1.

Most Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) now provide a intermediate certificate that has not been signed with SHA1 as a alternative to download and use.

Newer options include free certificates from [Let's Encrypt](https://letsencrypt.org/) which will provide a actual signed certificate that can be used for local/internal and public sites.  Which takes the management out of the server admin's hands to fix these problems.

Providers like [Cloudflare](https://www.cloudflare.com) have also started providing SSL certificates for any websites going through their proxy, making it easy to give any website HTTPS if there is no control over the actual web server.

# Resources

* [SSL Certificate framework 101: How does the browser actually verify the validity of a given server certificate?](http://security.stackexchange.com/questions/56389/ssl-certificate-framework-101-how-does-the-browser-actually-verify-the-validity)
* [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority)