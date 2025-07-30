import os
from asn1crypto.cms import RecipientInfo, KeyTransRecipientInfo, RecipientIdentifier, KeyEncryptionAlgorithm, \
    KeyEncryptionAlgorithmId, EnvelopedData, EncryptedContentInfo, ContentType, IssuerAndSerialNumber, RecipientInfos
from asn1crypto.core import OctetString
from asn1crypto.algos import EncryptionAlgorithmId, EncryptionAlgorithm

from enum import Enum
from abc import ABCMeta, abstractmethod
from scepreq.cryptoutils import encrypt


class EncryptionCipher(Enum):
    AES = 'aes'
    TRIPLEDES = 'tripledes_3key'


class PKIEnvelopeBuilder(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def encrypt(self, data, algorithm = None):
        return NotImplemented

    @abstractmethod
    def add_recipient(self, certificate):
        return NotImplemented

    @abstractmethod
    def finalize(self):
        return NotImplemented


class PKCSPKIEnvelopeBuilder(object):
    """Build a PKCSPKIEnvelope (envelopedData + encryptedContentInfo) as per SCEP RFC

    This builder encrypts content and adds recipients who may decrypt that content.
    """

    def __init__(self):
        self._data = None
        self._encryption_algorithm_id = None
        self._recipients = []

    def encrypt(self, data, algorithm = None):
        """Set the data to be encrypted.

        The algorithm option is not yet available, and will default to 3DES-CBC.

        Args:
              data (bytes): The data to encrypt
              algorithm (str): RESERVED FOR FUTURE USE
        Returns:
              PKCSPKIEnvelopeBuilder
        """
        self._data = data
        if algorithm == '3des':
            self._encryption_algorithm_id = EncryptionAlgorithmId(u'tripledes_3key')
        elif algorithm == 'aes128':
            self._encryption_algorithm_id = EncryptionAlgorithmId(u'aes128_cbc')
        elif algorithm == 'aes256':
            self._encryption_algorithm_id = EncryptionAlgorithmId(u'aes256_cbc')
        else:
            raise ValueError('Unrecognised encryption algorithm ', algorithm)

        return self

    def add_recipient(self, certificate):
        """Add a recipient for the encrypted data.

        Args:
              certificate (x509.Certificate): The recipients certificate, used to encrypt the symmetric key.
        Returns:
              PKCSPKIEnvelopeBuilder
        """
        self._recipients.append(certificate)

        return self

    def _encrypt_data(self, data):
        """Build the ciphertext of the ``messageData``.

        Args:
              data (bytes): Data to encrypt as the ``messageData`` of the SCEP Request

        Returns:
              Tuple of 3DES key, IV, and cipher text encrypted with 3DES
        """
        cipher = 'des'
        mode = 'cbc'
        key = None
        iv = None
        if self._encryption_algorithm_id.native == 'tripledes_3key':
            key = os.urandom(24)
            iv = os.urandom(8)
            cipher = '3des'
        elif self._encryption_algorithm_id.native == 'aes128_cbc':
            key = os.urandom(16)
            iv = os.urandom(16)
            cipher = 'aes'
        elif self._encryption_algorithm_id.native == 'aes256_cbc':
            key = os.urandom(32)
            iv = os.urandom(16)
            cipher = 'aes'

        return encrypt(cipher=cipher, mode=mode, key=key, iv=iv, plain_content=data)

    def _build_recipient_info(self, symmetric_key, recipient):
        """Build an ASN.1 data structure containing the encrypted symmetric key for the encrypted_content.

        NOTE: The recipient is always identified by issuerAndSerialNumber
        NOTE:

        Args:
            symmetric_key (bytes): Typically the randomly generated 3DES key for the encrypted_content.
            recipient (x509.Certificate): The certificate which will be used to encrypt the symmetric key.

        Returns:
              RecipientInfo: Instance of ASN.1 data structure with required attributes and encrypted key.
        """
        encrypted_symkey = recipient.public_key.encrypt(
            plaintext=symmetric_key,
            padding_type='pkcs'
        )
        asn1cert = recipient.to_asn1_certificate()
        ias = IssuerAndSerialNumber({
            'issuer': asn1cert.issuer,
            'serial_number': asn1cert.serial_number
        })

        ri = RecipientInfo('ktri', KeyTransRecipientInfo({
            'version': 0,
            'rid': RecipientIdentifier('issuer_and_serial_number', ias),
            'key_encryption_algorithm': KeyEncryptionAlgorithm({'algorithm': KeyEncryptionAlgorithmId(u'rsa')}),
            'encrypted_key': encrypted_symkey,
        }))

        return ri

    def finalize(self):
        """Encrypt the data and process the key using all available recipients.

        Returns:
              EnvelopedData, TripleDES, iv (bytes): The PKCSPKIEnvelope structure, The symmetric key, and the IV for
              the symmetric key.
        """
        key, iv, ciphertext = self._encrypt_data(self._data)

        eci = EncryptedContentInfo({
            'content_type': ContentType(u'data'),
            'content_encryption_algorithm': EncryptionAlgorithm({
                'algorithm': self._encryption_algorithm_id,
                'parameters': OctetString(iv),
            }),
            'encrypted_content': ciphertext,
        })

        recipients = [self._build_recipient_info(key, recipient) for recipient in self._recipients]
        recipient_infos = RecipientInfos(recipients)

        ed = EnvelopedData({
            'version': 1,
            'recipient_infos': recipient_infos,
            'encrypted_content_info': eci,
        })

        return ed, key, iv
