HTTPS has become a important part of keeping users safe on the web. With new tools/protocols (HTTPv2) that only operate over SSL the importance is clear.

While not a issue per-say websites are recommended to look at enabling HTTPs for their users. This might not always be possible but should be strongly considered.

Search engines like Google have also been taking a interest by including SSL as a ranking signal in their algorithm. 

# How do I fix this ?

There are 2 options here, both leading to HTTPS for your website.

Option number 1 is that services like [cloudflare.com](https://cloudflare.com) offer SSL for free to all their customers. If you do not control the server (shared hosting) or simply looking for a quick generic fix this is a great (and quick) option.

Option number 2 is a bit more involved but will put you in control. That is buying a certificate from a SSL provider and enabling it in your web server config.

Following these steps you'll come out above, we've provided more details information under "SSL certificates" while providing a quick overview here:

* Decide on the level of certificate you're domain/business requires. These include Domain Validated, Company Validated or Extended Validation.
* Generate a private key that you'll keep private
* Sign a CSR (Certificate Signing Request) with that private key
* Head to a Certificate Authority that will sign and give you a certificate ready for use. Some examples include [GeoTrust](https://www.geotrust.com/), [DigiCert](http://www.digicert.com/), [Thawte](http://www.thawte.com/) and [www.symantec.com](http://www.symantec.com/verisign/ssl-certificates)
* Enable the certificate that your provider has sent on your web server.

See "SSL certificates" for more details on all these steps.

# SSL Certificates


## Certificate Types

There are mainly 3 types of certificates:

* **Domain Validated / Low Assurance**: These Certificates are fully supported and share the same browser recognition with
Organization validated certificates, but come with the advantage of being 
issued almost immediately and without the need to submit company paperwork. 
This makes the certificate ideal for businesses needing a low cost SSL quickly and 
without the effort of submitting company documents. Only your domain name will 
be included in the certificate and not the business name and the required check 
is mostly done by just checking your WHOIS record. As the name implies, they 
provide less assurance to your customers.
* **Company Validated / High Assurance**: A high assurance certificate is the normal type of certificate that is issued. There 
are two things that must be verified before you can be issued a high assurance 
certificate: ownership of the domain name and valid business registration. 
Both of these items are listed on the certificate so visitors be be sure that 
you are who you say you are. Because it requires manual validation, high
assurance certificates can take an hour to a few days to be issued. These 
certificates include the actual organization name and domain in the certificate.
* **Extended Validation**: An EV certificate is a new type of certificate that is designed to prevent phishing 
attacks. It requires extended validation of your business and authorization to order 
the certificate and can take a few days to a few weeks to receive. It provides even 
greater assurance to customers than high assurance certificates by making the 
address bar turn green and displaying the company name too.

## Steps to buying a certificate

### Step 1: Decide on a Certificate Type

Different organizations have different needs so selecting the correct type is important. See "Certificate Types" for all the juicy details.

### Step 2: Generate your Private Key

[OpenSSL](http://www.openssl.org/) is a open source toolkit that is installed by default on most systems. It can be used to generate all the required keys you need.

To generate a private key with the name private_key.pem of 2048 bit, you would use the following command:

````
openssl genrsa -des3 -out private.key 2048
````

### Step 3: Create a Certificate Signing Request

[OpenSSL](http://www.openssl.org/) is our toolkit of choice again. Using your private key we created in the first step us:

````
openssl req -new -key private.key -out request.csr
````

### Step 4: Head to your Certificate Authority

Head over to any of these well known SSL auhorities:

* [GeoTrust](https://www.geotrust.com/)
* [DigiCert](http://www.digicert.com/)
* [Thawte](http://www.thawte.com/)
* [www.symantec.com](http://www.symantec.com/verisign/ssl-certificates)

### Step 5: Configure Web Server

Depending on your type of web server this config could differ. We tried to common the classics, namely **NGINX** and **Apache**.

#### NGINX

````
server {
    listen              443 ssl;
    server_name         www.example.com;
    ssl_certificate     www.example.com.crt;
    ssl_certificate_key www.example.com.key;
    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ...
}
````

#### Apache

````
<VirtualHost 192.168.0.1:443>
DocumentRoot /var/www/html2
ServerName www.yourdomain.com
SSLEngine on
SSLCertificateFile /path/to/your_domain_name.crt
SSLCertificateKeyFile /path/to/your_private.key
SSLCertificateChainFile /path/to/DigiCertCA.crt
</VirtualHost>
````

#### Step 6: 

Rest easy that your users are now more secure !

# Resources


* [HTTPS as a ranking signal](https://googlewebmastercentral.blogspot.co.za/2014/08/https-as-ranking-signal.html)
* [Apache SSL Certificate Installation](https://www.digicert.com/ssl-certificate-installation-apache.htm)
* [NGINX - Configuring HTTPS servers](http://nginx.org/en/docs/http/configuring_https_servers.html)
* [How to create a certificate - step-by-step process, we got your back !](https://atomcert.com/how)
