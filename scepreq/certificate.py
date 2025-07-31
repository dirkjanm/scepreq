from asn1crypto import x509, pem
from oscrypto import asymmetric, keys
import binascii

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .privatekey import PrivateKey
from .publickey import PublicKey


class Certificate:
    @classmethod
    def from_p12_file(cls, p12_file, password=None):
        with open(p12_file, 'rb') as file_handle:
            private_key_info, certificate, chain = keys.parse_pkcs12(file_handle.read(), password=password)
            cert = cls(certificate=certificate)
            private_key = PrivateKey(private_key=private_key_info)

            return cert, private_key

    @classmethod
    def from_pem_file(cls, pem_file):
        with open(pem_file, 'rb') as pem_file_handle:
            return cls.from_pem(pem_file_handle.read())

    @classmethod
    def from_pem(cls, pem_string):
        _, _, der_bytes = pem.unarmor(pem_string)
        return cls.from_der(der_bytes)

    @classmethod
    def from_der_file(cls, der_file):
        with open(der_file, 'rb') as der_file_handle:
            return cls.from_der(der_file_handle.read())

    @classmethod
    def from_der(cls, der_string):
        return cls(der_string=der_string)

    def __init__(self, der_string=None, certificate=None):
        if certificate is None:
            self._certificate = x509.Certificate.load(der_string)
        else:
            self._certificate = certificate
        self._crypto_certificate = crypto_x509.load_der_x509_certificate(self._certificate.dump(), default_backend())

    @property
    def public_key(self):
        return PublicKey(public_key=self._certificate.public_key)

    @property
    def self_signed(self):
        return (self._certificate['tbs_certificate']['issuer'] ==
                self._certificate['tbs_certificate']['subject'])

    @property
    def subject(self):
        # self.to_crypto_certificate().subject.rfc4514_string()
        return self._certificate['tbs_certificate']['subject']

    @property
    def subject_dict(self):
        return self.subject.native

    @property
    def issuer(self):
        return self._certificate['tbs_certificate']['issuer']

    @property
    def issuer_dict(self):
        return self.issuer.native

    @property
    def serial_number(self):
        return self._certificate['tbs_certificate']['serial_number'].native

    @property
    def begin_date(self):
        return self._crypto_certificate.not_valid_before

    @property
    def end_date(self):
        return self._crypto_certificate.not_valid_after

    @property
    def thumbprint(self):
        certbytes = asymmetric.dump_certificate(self._certificate, encoding='der')
        digest = hashes.Hash(hashes.SHA1())
        digest.update(certbytes)
        thumbprint = digest.finalize()
        hfthumbprint = binascii.hexlify(thumbprint).decode('utf-8').upper()
        return hfthumbprint

    @property
    def key_usage(self):
        # Having the key_usage field can be optional.
        # ref: https://security.stackexchange.com/questions/68491/recommended-key-usage-for-a-client-certificate
        # ref: https://docs.digicert.com/en/trust-lifecycle-manager/certificates/certificate-attributes-and-extensions/key-usage.html
        if self._certificate.key_usage_value:
            return self._certificate.key_usage_value.native
        return None

    @property
    def is_ca(self):
        return self._certificate.ca

    def to_der(self):
        return asymmetric.dump_certificate(self._certificate, encoding='der')

    def to_pem(self):
        return asymmetric.dump_certificate(self._certificate, encoding='pem')

    def to_crypto_certificate(self):
        return self._crypto_certificate

    def to_asn1_certificate(self):
        return self._certificate

    def verify(self, signature, padding_type, digest_algorithm, data):
        return self.public_key.verify(signature=signature, padding_type=padding_type, digest_algorithm=digest_algorithm, data=data)
