OCSP (*Online Certificate Status Protocol*) stapling allows CA's to revoke the status of a certificate and present a signed message to clients that are connecting to a SSL server. This allows users to check the status of a certificate without having to query the CA directly moving the cost to the server away from the client.

It was created as an alternative to CRL to reduce the SSL negotiation time. With CRL (Certificate Revocation List) the browser downloads a list of revoked certificate serial numbers and verifies the current certificate, which increases the SSL negotiation time.

While another option to use [*TLS Certificate Status Request extension*](https://tools.ietf.org/html/rfc6961) exists, OSCP gives clients a extra layer of security without any extra processing.

When a certificate is revoked via OCSP clients will be presented with a warning.

# How do I fix this ?

Follow up with your configured certificate making sure that the CA has not revoked the certificate.

# Resources

* [OCSP stapling](https://en.wikipedia.org/wiki/OCSP_stapling)
