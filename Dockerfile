# Base image for ubuntu 14.04
FROM gcr.io/passmarked/base:latest

# update to a newer version of openssl
RUN apt-get update
RUN apt-get install -y wget openssl libssl-dev

# install our essentials to build openssl
RUN apt-get install -y build-essential 

# upgrade to a much newer and specific version of ssl
RUN wget -O /tmp/openssl-1.0.2h.tar.gz https://package.passmarked.com/openssl/src/openssl-1.0.2h.tar.gz
RUN cd /tmp/ && tar -xf /tmp/openssl-1.0.2h.tar.gz
RUN rm /tmp/openssl-1.0.2h.tar.gz
RUN cd /tmp/openssl-1.0.2h && ./config
RUN cd /tmp/openssl-1.0.2h && make depend
RUN cd /tmp/openssl-1.0.2h && make
RUN cd /tmp/openssl-1.0.2h && make install
RUN rm -R /tmp/openssl-1.0.2h

# install ca certs
RUN apt-get install -y ca-certificates