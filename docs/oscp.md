OCSP (*Online Certificate Status Protocol*) stapling allows CA's to revoke the status of a certificate and present a signed message to clients that are connecting to a SSL server. This allows users to check the status of a certificate without having to query the CA directly moving the cost to the server away from the client.

It was created as an alternative to CRL to reduce the SSL negotiation time. With CRL (Certificate Revocation List) the browser downloads a list of revoked certificate serial numbers and verifies the current certificate, which increases the SSL negotiation time.

While another option to use [*TLS Certificate Status Request extension*](https://tools.ietf.org/html/rfc6961) exists, OSCP gives clients a extra layer of security without any extra processing.

When a certificate is revoked via OCSP clients will be presented with a warning.
 
# How do I fix this ?
 
The OCSP can be configured in your favourite web server:
 
## NGINX
 
In a server block for the website add the following config:
 
```
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/private/ca-certs.pem;
```

## Testing

To test run the following:

```
echo QUIT | openssl s_client -connect example.com:443 -status 2> /dev/null | grep -A 17 'OCSP response:' | grep -B 17 'Next Update'
```

Which should show something like the following:

```
OCSP response:
======================================
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: 4C58CB25F0414F52F428C881439BA6A8A0E692E5
    Produced At: May  9 08:45:00 2014 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: B8A299F09D061DD5C1588F76CC89FF57092B94DD
      Issuer Key Hash: 4C58CB25F0414F52F428C881439BA6A8A0E692E5
      Serial Number: 0161FF00CCBFF6C07D2D3BB4D8340A23
    Cert Status: good
    This Update: May  9 08:45:00 2014 GMT
    Next Update: May 16 09:00:00 2014 GMT
```

## Apache

In the configuration block for the requested domain add the following config:

```
SSLCACertificateFile /etc/ssl/ca-certs.pem
SSLUseStapling on
```
 
# Resources
 
 * [OCSP stapling](https://en.wikipedia.org/wiki/OCSP_stapling)
 * [How To Configure OCSP Stapling on Apache and Nginx](https://www.digitalocean.com/community/tutorials/how-to-configure-ocsp-stapling-on-apache-and-nginx)
