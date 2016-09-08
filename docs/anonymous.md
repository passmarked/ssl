Anonymous ciphers were introduced to be used in scenarios where only opportunistic encryption can be can be created, when no set-up for authentication is in place. One common example of this is emails, the idea was that clients could request a Anonymous cipher and save the server the generation of a SSL handshake.

Moving to HTTP and HTTPS these ciphers are more dangerous than good, and it recommended that they are disabled on the server serving the SSL information.

# How do I fix this ?

To fix make sure that the server is not configured to announce and support any Anonymous ciphers.

For a quick start the following can be used:

```ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:-LOW:-SSLv2:-EXP:!kEDH:!aNULL```

take of the `!aNULL`, `!kEDH` and `!ADH`, which have been negated from the chipher list.

# Resources

* [In which cases can an SSL server omit sending the certificate?](http://stackoverflow.com/questions/8413093/in-which-cases-can-an-ssl-server-omit-sending-the-certificate)
* [IIS: serve site anonymously to intranet but through SSL and basic auth to internet](http://serverfault.com/questions/749512/iis-serve-site-anonymously-to-intranet-but-through-ssl-and-basic-auth-to-intern)
* [SSL/TLS - Typical problems and how to debug them](http://noxxi.de/research/ssl-debugging.html)
* [How to disable anonymous (insecure) suites ? Ref: SSLLABS](https://forums.cpanel.net/threads/how-to-disable-anonymous-insecure-suites-ref-ssllabs.423541/)
