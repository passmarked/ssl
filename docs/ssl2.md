SSL is a cryptographic protocol used for obscuring data during transmission. The second revision of SSL is over two decades old and has numerous known vulnerabilities. Disabling support on your server will disallow clients from using this insecure protocol.

# How do I fix this?

* Apache:
  + Add the following to your global configuration and/or update existing virtual-hosts with the following: `SSLProtocol All -SSLv2 -SSLv3`
  + Execute at your terminal prompt: `sudo apache2ctl configtest && sudo service apache2 restart`
* IIS:
  + Add the following to a file named `disable_ssl3.reg`:
  ```
  Windows Registry Editor Version 5.00
  [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server]
  "Enabled"=dword:00000000
  [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server]
  "Enabled"=dword:00000000
  ```
  + Execute the file once you've created it to apply the registry changes.
* Nginx:
  + Add the following to your global configuration and/or update existing virtual-hosts with the following: `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;`
  + Then restart Nginx with: `sudo service nginx restart`

Test your server using zmap, or manually with: `openssl s_client -connect <host>:<port> -ssl2`. Consider the test a success if a *handshake error* is returned from `openssl`.

# Resources

* [zmap SSLv3 Test](https://zmap.io/sslv3/sslv3test.html)
* [Disable SSL3](http://disablessl3.com/)
