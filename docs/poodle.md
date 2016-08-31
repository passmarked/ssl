POODLE stands for “Padding Oracle On Downgraded Legacy Encryption.” It relies on the presence of SSLv3 and/or TLS 1.0 - 1.2. An attacker could use this exploit to uncover encrypted data during its transmission between the client or the server.

# How do I fix this?

Prevention of the POODLE exploit is achieved by disabling SSLv3 for client and server. However, some older clients and servers do not support TLS 1.0 and above. Therefore, the browser and server implementation of TLS_FALLBACK_SCSV is recommended to make downgrade attacks impossible.

# Resources

* [POODLE](https://en.wikipedia.org/wiki/POODLE)
* [CVE-2014-3566](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566)
