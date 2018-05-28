# update to a newer version of openssl
RUN apt-get -y update
RUN apt-get install -y wget openssl libssl-dev

# install our essentials to build openssl
RUN apt-get install -y build-essential 

# upgrade to a much newer and specific version of ssl
RUN wget -O /tmp/openssl-1.0.2n.tar.gz https://package.passmarked.com/openssl/src/openssl-1.0.2n.tar.gz
RUN cd /tmp/ && tar -xf /tmp/openssl-1.0.2n.tar.gz
RUN rm /tmp/openssl-1.0.2n.tar.gz
RUN cd /tmp/openssl-1.0.2n && ./config
RUN cd /tmp/openssl-1.0.2n && make depend
RUN cd /tmp/openssl-1.0.2n && make
RUN cd /tmp/openssl-1.0.2n && make install
RUN rm -R /tmp/openssl-1.0.2n

# install ca certs
RUN apt-get install -y ca-certificates