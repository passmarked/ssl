[Server Name Indication (SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication) provides a way for servers to host multiple SSL domains, where in the past only one domain per IP could be configured.

Clients have been defaulting to expecting SNI to be enabled on a server, so to avoid any unexpected behaviour servers should look into enabling SNI. Gaining the extra option of hosting more domains on the same IP, which is a **BIG** plus.

Olders clients such as Windows XP using MSIE do not support SNI, and enabling could cause issues for clients using those systems. It is thus advised to make a informed decision on this for your specific use case.

# How do I fix this?

Most newer web servers like NGINX / Apache would have SNI enabled by default. Find and disable the command currently disabling the setting.

Apache will make use of SNI when virtual hosts are configured by default as well.

# Resources

* [Server Name Indication](https://en.wikipedia.org/wiki/Server_Name_Indication)
* [How To Set Up Multiple SSL Certificates on One IP with Apache on Ubuntu 12.04](https://www.digitalocean.com/community/tutorials/how-to-set-up-multiple-ssl-certificates-on-one-ip-with-apache-on-ubuntu-12-04)