#!/bin/bash
if [[ $UPGRADE_OPENSSL == "true" || $UPGRADE_OPENSSL == "1" ]]; then
	echo "Upgrading OpenSSL..."
	echo "Before:"
	openssl version
	echo "Downloading..."
	wget -nv http://ftp.us.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.0f-3+deb9u1_amd64.deb -O /tmp/libssl.deb
	wget -nv http://ftp.us.debian.org/debian/pool/main/o/openssl/openssl_1.1.0f-3+deb9u1_amd64.deb -O /tmp/openssl.deb
	dpkg -i /tmp/libssl.deb
	dpkg -i /tmp/openssl.deb
	echo "After:"
	openssl version
fi
