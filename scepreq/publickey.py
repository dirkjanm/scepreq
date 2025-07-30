from asn1crypto import pem
from oscrypto import asymmetric, keys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from scepreq.cryptoutils import padding_for_type, digest_function_for_type


class PublicKey:
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

    def __init__(self, der_string=None, public_key=None):
        if public_key is None:
            self._public_key = keys.parse_public(der_string)
        else:
            self._public_key = public_key

        self._oscrypto_public_key = asymmetric.load_public_key(source=self._public_key)
        self._crypto_public_key = serialization.load_der_public_key(data=self.to_der(), backend=default_backend())

    def to_der(self):
        return asymmetric.dump_public_key(self._public_key, encoding='der')

    def to_pem(self):
        return asymmetric.dump_public_key(self._public_key, encoding='pem')

    def to_crypto_public_key(self):
        return self._crypto_public_key

    def to_asn1_public_key(self):
        return self._public_key

    def encrypt(self, plaintext, padding_type):
        padding = padding_for_type(padding_type=padding_type)
        return self._crypto_public_key.encrypt(plaintext=plaintext, padding=padding)

    def verify(self, signature, padding_type, digest_algorithm, data):
        algorithm = digest_function_for_type(algorithm=digest_algorithm)
        hasher = algorithm()
        padding = padding_for_type(padding_type=padding_type, hash_algo=hasher)
        return self._crypto_public_key.verify(signature, data, padding, hasher)
        # verifier = self._crypto_public_key.verifier(signature, padding, algorithm())
        # verifier.update(data)
        # if data1:
        #     verifier.update(data1)
        #
        # return verifier.verify()

