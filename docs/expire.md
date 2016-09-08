To provide the `https://` and green status bar a SSL Certificate is bought and used. This certificate is valid for a certain period (normally at a mimimum a year).

When the certificate expires users to the website no longer receive a green status bar, instead showing a alert.

The tested website contained a certificate that is about to expire, giving the users a danger of not being able to access the website securely once expired.

# How do I fix this ?

By either buying a new certificate for the domains, making sure to include all the required domains. 

Newer options include free certificates from [Let's Encrypt](https://letsencrypt.org/) which will provide a actual signed certificate that can be used for local/internal and public sites. 

Providers like [Cloudflare](https://www.cloudflare.com) have also started providing SSL certificates for any websites going through their proxy, making it easy to give any website HTTPS if there is no control over the actual web server.

# Resources

* [Let's Encrypt](https://letsencrypt.org/)
* [Certificate has either expired or has been revoked](http://stackoverflow.com/questions/36689116/certificate-has-either-expired-or-has-been-revoked/37080603)
