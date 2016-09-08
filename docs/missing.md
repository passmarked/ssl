The server did not respond with a certificate. These are rare cases but a serious problem. 

The connection took place but no certificate was presented over the TLS connection, this most likely points to a incorrectly configured server.

# How do I fix this ?

Ensure to follow guides on configuring the SSL certificates on your web server after doing a few requests usings tools like CURL for example:

```
curl https://example.com
```

# Resources

* [CURL](https://curl.haxx.se/)