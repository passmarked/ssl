TLS has become the defacto protocol for encryption over the web, after the serious exploits of SSL, the move to TLS has been more important than ever.

Web servers are expected to support TLS v1 / v1.1 / v1.2 for users to operate at the recommended level of security.

# How do I fix this ?

Ensure that your chosen web server config has the TLS protocol versions enabled.

# NGINX

In the server block for your hostname ensure the following config line is present:

```
ssl_protocols TLSv1 TLSv1.1 TLSv1.2
```

# Apache

In the configuration for the virtualhost add the following:

```
SSLProtocol -all +TLSv1.1 +TLSv1.2
```

Take not of the negated `-all` that stops all protocols from being usable.

# Resources

* [ssl_protocols](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols)
* [Apache SSLProtocol -all +TLSv1.1 +TLSv1.2 Assessment failed: Unexpected error](https://community.qualys.com/thread/13903)
* [Security/Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)
* [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security)
