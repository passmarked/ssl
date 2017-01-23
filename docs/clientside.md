HTTPS/SSL allows you to encrypt traffic and keep content users receive a secret.

But when the initial request to the site does not simply redirect and opens a page. That content could be exposed to prying eyes, and secrets leaked like passwords.

Using client-side redirections are fine for simple redirects but using it to switch between plain text and secure is a huge security problem.

Some browsers might not even support Javascript or contain security settings that disallow changing the url on the client-side. This would cause those users to use the plain text website exposing them to various privacy issues online.

These redirects (apart from the security issues) are also not cachable by the browsers.

# How do I fix this?

Update the servers to use server-side status codes `301` or `302` to redirect.

# Resources

* [Let's Encrypt](https://letsencrypt.org)
* [Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)
* [StackExchange: How is it possible that people observing an HTTPS connection being established wouldn't know how to decrypt it?](http://security.stackexchange.com/questions/6290/how-is-it-possible-that-people-observing-an-https-connection-being-established-w/6296#6296)
* [StackExchange: Understanding 2048-bit SSL and 256-bit encryption](http://security.stackexchange.com/questions/19473/understanding-2048-bit-ssl-and-256-bit-encryption)
