The OSCP (*Online Certificate Status Protocol*) status returned from the server did not report success meaning the configured certificate and SSL config was not able to return a successfull status from the CA server.

OCSP stapling allows CA's to revoke the status of a certificate and present a signed message to clients that are connecting to a SSL server. This allows users to check the status of a certificate without having to query the CA directly moving the cost to the server away from the client.
 
 When a certificate is revoked via OCSP clients will be presented with a warning. 
 
 # How do I fix this ?
 
 Ensure that the configured certificate and OCSP settings are valid according to issued certificate.
 
 # Resources
 
 * [OCSP stapling](https://en.wikipedia.org/wiki/OCSP_stapling)
 * [How To Configure OCSP Stapling on Apache and Nginx](https://www.digitalocean.com/community/tutorials/how-to-configure-ocsp-stapling-on-apache-and-nginx)
