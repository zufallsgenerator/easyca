#!/bin/bash
echo "Downloading..."
wget -nv http://ftp.us.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.0l-1~deb9u1_amd64.deb -O /tmp/libssl.deb
wget -nv http://ftp.us.debian.org/debian/pool/main/o/openssl/openssl_1.1.0l-1~deb9u1_amd64.deb -O /tmp/openssl.deb
dpkg -x /tmp/libssl.deb /tmp/extracted
dpkg -x /tmp/openssl.deb /tmp/extracted

