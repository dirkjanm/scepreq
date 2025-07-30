from asn1crypto import crl, pem

from cryptography import x509 as crypto_x509
from cryptography.hazmat.backends import default_backend

from .certificate import Certificate


class RevocationList:
    PEM_MARKER = u'X509 CRL'

    def __init__(self, der_string=None, revocation_list=None):
        if revocation_list is None:
            self._revocation_list = crl.CertificateList.load(der_string)
        else:
            self._revocation_list = revocation_list

        self._crypto_revocation_list = crypto_x509.load_der_x509_crl(self._revocation_list.dump(), default_backend())

    @property
    def issuer(self):
        return self._revocation_list.issuer

    @property
    def critical_extensions(self):
        return self._revocation_list.critical_extensions

    @property
    def version(self):
        return self._revocation_list['tbs_cert_list']['version'].native

    @property
    def this_update(self):
        return self._revocation_list['tbs_cert_list']['this_update'].native

    @property
    def next_update(self):
        return self._revocation_list['tbs_cert_list']['next_update'].native

    @property
    def revoked_certificates(self):
        return [Certificate(certificate=cert) for cert in self._revocation_list['tbs_cert_list']['revoked_certificates']]

    def to_der(self):
        return self._revocation_list.dump()

    def to_pem(self):
        return pem.armor(type_name=self.PEM_MARKER, der_bytes=self.to_der())

    def to_crypto_certificate(self):
        return self._crypto_revocation_list

    def to_asn1_certificate(self):
        return self._revocation_list
