.. image:: https://travis-ci.org/zufallsgenerator/easyca.svg?branch=master
    :target: https://travis-ci.org/zufallsgenerator/easyca.svg?branch=master
EasyCA
******

Copyright (c) 2017 Christer Byström

This package provides convinience methods for creating Certificate
Authorities (CA), signing Certificate Signing Requests (CSR) and
creating self-signed certificates.

This is intended to be used for developing purposes to quickly
generate a root CA that can be used for signing test certificates
instead of having to install each new test certificate that is being
generated.

This package also supports using Subject Alternative Names for DNS and
IP addresses, as the Common Name (CN) attribute of the subject will be
deprecated at some point.

Under the hood the openssl cli and pyOpenSSL are used.

Python 3.4 and above supported.


API Reference
=============

**easyca.create_self_signed(dn=None, alt_names=None, days=90,
newkey='rsa:2048')**

   Create a self-signed certificate.

   :Parameters:
      * **dn** – a dictionary with configuration for distinguished
        name

      * **alt_names** – a list of of Subject Alternative Names

      * **days** – how many days in the future the CA will be valid

      * **newkey** – key specification like ‘rsa:2048’

   :Returns:
      a dict with the members *success* and *message* always set

**class easyca.CA(ca_path=None)**

   Bases: ``object``

   Certificate Authority, using an openssl CA folder structure as a
   flat-file database.

   :Parameters:
      **ca_path** – path where to create the required folder structure

   ``DB_VERSION = 1``

   **get_certificate(serial=None)**

      Get details of a signed certificate

   **get_info()**

      Get information about the CA in ca_path.

      :Parameters:
         **ca_path** – Path to Certificate Authority

      :Returns:
         JSON object with status

   **get_request(serial=None)**

      Get details of a certificate signing request

      :Parameters:
         **serial** – serial number of request

      :Returns:
         a dict with information

   **initialize(dn=None, alt_names=None, days=90, newkey='rsa:2048')**

      Initialize a Certificate Authority. This creates a folder
      structure containing a root CA, public and private keys, and
      folders for Certificate Signing Requests and SignedCertificates.

      :Parameters:
         * **dn** – a ``DistinguishedName`` or py:class:*dict*

         * **alt_names** – a list of of Subject Alternative Names

         * **days** – how many days in the future the CA will be valid

         * **newkey** – key specification like ‘rsa:2048’

      :Returns:
         a dict with the members *success* and *message* always set

   ``initialized``

      :Returns boolean:
         true if initialized

   **list_certificates()**

      Get a list of signed certificates

   **list_requests()**

      Get a list of Certificate Signing Requests.

      :Returns:
         list – a list of {“id”: <id>, “last_modified”: <datastring>}

   **revoke_certificate(serial=None)**

   **sign_request(csr=None, days=90)**

      Sign a Certificate Signing Request. This function carries over
      Subject Alternative Name entries from the request.

      :Parameters:
         * **csr** – a string with the CSR in PEM format

         * **days** – how many days in the future the certificate will
           be valid

      :Returns:
         a dict with the members *success* and *message* always set

**class easyca.DistinguishedName(c=None, cn=None, email=None, l=None,
o=None, ou=None, st=None)**

   Bases: ``dict``

   Distinguished Name.

   :Parameters:
      * **c** – Country/Region (two letters)

      * **cn** – Common Name - hostname or dns

      * **email** – Email address

      * **l** – Locality

      * **o** – Organization Name

      * **ou** – Organizational Unit

      * **st** – State or Province
