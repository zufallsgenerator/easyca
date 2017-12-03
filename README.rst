.. image:: https://travis-ci.org/zufallsgenerator/easyca.svg?branch=master
    :target: https://travis-ci.org/zufallsgenerator/easyca.svg?branch=master

`Copyright (c) 2017 Christer Byström, MIT License`

This package provides convinience methods for creating
Certificate Authorities (CA), signing Certificate Signing Requests (CSR) and
creating self-signed certificates.

This is intended to be used for developing purposes to quickly generate
a root CA that can be used for signing test certificates instead of having to
install each new test certificate that is being generated.

This package also supports using Subject Alternative Names for DNS and IP
addresses, as the Common Name (CN) attribute of the subject will be deprecated
at some point.

Under the hood the openssl cli and pyOpenSSL are used.

Python 3.4 and above supported.
