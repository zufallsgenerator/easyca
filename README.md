[![build status](https://api.travis-ci.org/zufallsgenerator/dev_ssl_ca.svg?branch=master)](https://travis-ci.org/zufallsgenerator/dev_ssl_ca)

A wrapper around openssl and pyOpenSSL to create a Certificate Authority and sign Certificates.
Also provides and extract information from ssl certificates in PEM (text, base64-encoded) format.

To be used for development purposes when one quickly needs to create and sign a certificate.

Subject Alternative Name (SAN) for self-signed certificates is supported.

Python 3.4 and above supported.
