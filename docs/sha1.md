[Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority)'s often issue [Intermediate certificates](https://en.wikipedia.org/wiki/Intermediate_Certificate_Authority) that are used to sign and create new certificates.

All certificates along the chain of issued/signed certificates are important to keep secure and make sure they are using the latest ciphers.

This error indicates a certificates in the chain is still using a SHA1 hashing cipher. In 2017, Google announced that they had [found a collision in SHA1(https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html). Which means these hash functions are no longer seen as secure. 

While SHA1 is not as totally broken and open to preimage as MD5 is now; this does mean given enough time and progression of computing power attacks could later derive the SHA1 certificates from the signature itself.

To sum up this issue:

> If an intermediate or end certificate has a weak signature, then it is possible that an attacker can generate two certificates with the same signature with different encoded information (e.g. looks-harmless.com and your-bank.com). The attacker can then ask a certificate authority to sign one of the certificate (looks-harmless.com) then copied the signature to the other certificate (your-bank.com).

> The problem with SHA1 is that it has flaws that renders it feasible for an attacker with sufficient resource to find such collisions.

# How do I fix this ?

Look into issueing certificates from CA's using SHA256 (at a minimum) to hash their signatures. Many CA's offer both for compatability reasons.

# Resources

* [An update on SHA-1 certificates in Chrome](https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html)
* [Why are Root CAs with SHA1 signatures not a risk](https://superuser.com/questions/1122069/why-are-root-cas-with-sha1-signatures-not-a-risk)
* [SHA 1 no impact to root certificate](https://security.stackexchange.com/questions/120301/sha-1-no-impact-to-root-certificate)
* [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority)