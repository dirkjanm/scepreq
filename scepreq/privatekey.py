from asn1crypto import pem
from oscrypto import asymmetric, keys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from scepreq.cryptoutils import padding_for_type, digest_function_for_type
from scepreq.publickey import PublicKey


class PrivateKey:
    @classmethod
    def from_pem_file(cls, pem_file, password=None):
        with open(pem_file, 'rb') as pem_file_handle:
            return cls.from_pem(pem_file_handle.read(), password=password)

    @classmethod
    def from_pem(cls, pem_string, password=None):
        _, _, der_bytes = pem.unarmor(pem_string)
        return cls.from_der(der_bytes, password=password)

    @classmethod
    def from_der_file(cls, der_file, password=None):
        with open(der_file, 'rb') as der_file_handle:
            return cls.from_der(der_file_handle.read(), password=password)

    @classmethod
    def from_der(cls, der_string, password=None):
        return cls(der_string=der_string, password=password)

    def __init__(self, der_string=None, password=None, private_key=None):
        if private_key is None:
            self._private_key = keys.parse_private(der_string, password=password)
        else:
            self._private_key = private_key

        self._oscrypto_private_key = asymmetric.load_private_key(source=self._private_key)
        self._crypto_private_key = serialization.load_der_private_key(data=self.to_der(), backend=default_backend(), password=None)

    @property
    def public_key(self):
        return PublicKey(public_key=self._oscrypto_private_key.public_key.asn1)

    def to_der(self, password=None):
        return asymmetric.dump_private_key(self._private_key, passphrase=password, encoding='der')

    def to_pem(self, password=None):
        return asymmetric.dump_private_key(self._private_key, passphrase=password, encoding='pem')

    def to_crypto_private_key(self):
        return self._crypto_private_key

    def to_asn1_private_key(self):
        return self._private_key

    def sign(self, data, padding_type, algorithm):
        digest_function = digest_function_for_type(algorithm=algorithm)
        padding = padding_for_type(padding_type=padding_type, hash_algo=digest_function)

        return self._crypto_private_key.sign(data=data, padding=padding, algorithm=digest_function())

    def decrypt(self, ciphertext, padding_type):
        padding = padding_for_type(padding_type=padding_type)
        return self._crypto_private_key.decrypt(ciphertext=ciphertext, padding=padding)
