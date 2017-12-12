#!/usr/bin/env python3


class DuplicateRequestError(Exception):
    pass


class OpenSSLError(Exception):
    def __init__(self, message=None, text=None):
        self.text = text
        return super().__init__(message)


def get_exception_from_openssl_output(text):
    for line in [l.strip() for l in text.splitlines()]:
        if line.endswith('Expecting: CERTIFICATE REQUEST'):
            return ValueError('Not a certificate request')
        if line == 'TXT_DB error number 2':
            return DuplicateRequestError(
                'A valid certificate with the same DISTINGUISHED NAME '
                'already exists')
        if (
            line ==
            'The commonName field needed to be supplied and was missing'
        ):
            return ValueError('commonName missing in request')
        if line.startswith('ERROR:Already revoked'):
            return OpenSSLError('Certificate already revoked')

    return OpenSSLError('Unknown openssl error', text=text)
