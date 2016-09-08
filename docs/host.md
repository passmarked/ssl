SSL certificates have a list of domains that the certificate is valid for, when connecting a users browser checks if the requested domain matches a hostname in the certificate along with verifying if from a trusted CA provider.

# How do I fix this ?

Ensure the provided certificate has the requested domain on it's list of supported domains. 

If the domain is new either a new certificate must be bought or created using newer providers like [Let's Encrypt](https://letsencrypt.org/) that provide free certificates for local/internal and public sites.

Providers like [Cloudflare](https://www.cloudflare.com) is also a option as all of their users receive a free certificate if proxying through their service.

# Resources

* [Name Mismatch in Web Browser](https://www.digicert.com/ssl-support/certificate-name-mismatch-error.htm)
