import logging
from base64 import b64encode
from asn1crypto.cms import CMSAttribute, ContentInfo, IssuerAndSerialNumber
from cryptography.hazmat.primitives.asymmetric import padding

from scepreq.asn1 import SCEPCMSAttributeType

from scepreq.cryptoutils import digest_for_data, decrypt, digest_function_for_type

from scepreq.enums import MessageType, PKIStatus
from scepreq.certificate import Certificate

CMSAttribute._fields = [
    ('type', SCEPCMSAttributeType),
    ('values', None),
]


logger = logging.getLogger(__name__)


def get_digest_method(name='sha1'):
    pass


class SCEPMessage(object):

    @classmethod
    def parse(cls, raw, signer_cert=None):
        msg = cls()

        cinfo = ContentInfo.load(raw)
        assert cinfo['content_type'].native == 'signed_data'

        # 1.2.840.113549.1.7.1
        signed_data = cinfo['content']

        if len(signed_data['certificates']) > 0:
            certs = [Certificate(certificate=cert.chosen) for cert in signed_data['certificates']]
            logger.debug('{} certificate(s) attached to signedData'.format(len(certs)))
            msg._certificates = certs
        else:
            certs = None
            logger.debug('No certificates attached to SignedData')

        # Iterate through signers and verify the signature for each.
        # Set convenience attributes at the same time
        for signer_info in cinfo['content']['signer_infos']:
            # version can be 1 (issuerandserial) or 3 (subjectkeyidentifier)
            assert signer_info['version'] != 'v1'  # we only support version 1
            identifier = signer_info['sid'].chosen
            assert isinstance(identifier, IssuerAndSerialNumber)  # TODO: also support other signer ids

            sig_algo = signer_info['signature_algorithm'].signature_algo
            logger.debug('Using signature algorithm: {}'.format(sig_algo))
            hash_algo = signer_info['digest_algorithm']['algorithm'].native
            logger.debug('Using digest algorithm: {}'.format(hash_algo))

            assert sig_algo == 'rsassa_pkcs1v15'  # We only support PKCS1v1.5

            if certs is not None and len(certs) > 0:  # verify content
                if signer_cert is None:
                    if certs is not None:
                        for c in certs:  # find signer cert
                            if c.serial_number == identifier['serial_number'].native:  # TODO: also convert issuer
                                signer_cert = c
                                break

            # Set the signer for convenience on the instance
            msg._signer_info = signer_info

            if 'signed_attrs' in signer_info:
                assert signed_data['encap_content_info']['content_type'].native == 'data'
                assert signer_cert is not None

                signed_attrs = signer_info['signed_attrs']
                signed_attrs_data = signed_attrs.dump()
                signed_attrs_data = b'\x31' + signed_attrs_data[1:]

                signer_cert.verify(
                    signature=signer_info.native['signature'],
                    padding_type='pkcs',
                    digest_algorithm=hash_algo,
                    data=signed_attrs_data
                )

                # signer_cert.verify(signature=signer_info['signature'].native, padding_type='pkcs', digest_algorithm=hash_algo, data=signer_info['signed_attrs'].dump())
                # /*
                # * Check that the signerinfo attributes obey the attribute rules which includes
                # * the following checks
                # * - If any signed attributes exist then there must be a Content Type
                # * and Message Digest attribute in the signed attributes.
                # * - The countersignature attribute is an optional unsigned attribute only.
                # * - Content Type, Message Digest, and Signing time attributes are signed
                # *     attributes. Only one instance of each is allowed, with each of these
                # *     attributes containing a single attribute value in its set.
                # */
                for signed_attr in signed_attrs:
                    name = SCEPCMSAttributeType.map(signed_attr['type'].dotted)

                    if name == 'transaction_id':
                        msg._transaction_id = signed_attr['values'][0].native
                    elif name == 'message_type':
                        msg._message_type = MessageType(signed_attr['values'][0].native)
                    elif name == 'sender_nonce':
                        msg._sender_nonce = signed_attr['values'][0].native
                    elif name == 'recipient_nonce':
                        msg._recipient_nonce = signed_attr['values'][0].native
                    elif name == 'pki_status':
                        msg._pki_status = PKIStatus(signed_attr['values'][0].native)
                    elif name == 'fail_info':
                        msg._fail_info = signed_attr['values'][0].native
                    elif name == 'content_type':
                        if msg._content_type is not None:
                            raise Exception('found multiple content_type in signed attributes')
                        msg._content_type = signed_attr['values'][0].native
                    elif name == 'signing_time':
                        if msg._signing_time is not None:
                            raise Exception('found multiple signing_time in signed attributes')
                        msg._signing_time = signed_attr['values'][0].native
                    elif name == 'message_digest':
                        if msg._message_digest is not None:
                            raise Exception('found multiple message_digest in signed attributes')
                        msg._message_digest = signed_attr['values'][0].native
                    elif name == 'algorithm_protection':
                        msg._algorithm_protection = signed_attr['values'][0].native

                assert msg._message_digest is not None
                assert msg._content_type is not None

                calculated_digest = digest_for_data(algorithm=hash_algo, data=signed_data['encap_content_info']['content'].native)
                assert msg._message_digest == calculated_digest

        msg._signed_data = cinfo['content']['encap_content_info']['content']

        return msg

    def __init__(self, message_type=MessageType.CertRep, transaction_id=None, sender_nonce=None,
                 recipient_nonce=None):
        self._content_info = None
        self._transaction_id = transaction_id
        self._message_type = message_type
        self._sender_nonce = sender_nonce
        self._recipient_nonce = recipient_nonce
        self._pki_status = None
        self._signer_info = None
        self._signed_data = None
        self._certificates = []
        self._content_type = None
        self._signing_time = None
        self._message_digest = None
        self._algorithm_protection = None

    @property
    def certificates(self):
        return self._certificates

    @property
    def transaction_id(self):
        return self._transaction_id

    @property
    def message_type(self):
        return self._message_type

    @property
    def sender_nonce(self):
        return self._sender_nonce

    @property
    def recipient_nonce(self):
        return self._recipient_nonce

    @property
    def pki_status(self):
        return self._pki_status

    @property
    def fail_info(self):
        return self._fail_info

    @property
    def signer(self):
        sid = self._signer_info['sid']
        if isinstance(sid.chosen, IssuerAndSerialNumber):
            issuer = sid.chosen['issuer'].human_friendly
            serial = sid.chosen['serial_number'].native

            return issuer, serial

    @property
    def encap_content_info(self):
        return ContentInfo.load(self._signed_data.native)

    @property
    def signed_data(self):
        return self._signed_data

    @signed_data.setter
    def signed_data(self, value):
        self._signed_data = value

    def get_decrypted_envelope_data(self, certificate, key):
        """Decrypt the encrypted envelope data:

        Decrypt encrypted_key using public key of CA
        encrypted_key is available at content.recipient_infos[x].encrypted_key
        algo is content.recipient_infos[x].key_encryption_algorithm
        at the moment this is RSA
        """
        encap = self.encap_content_info
        ct = encap['content_type'].native
        logger.debug('content_type is {}'.format(ct))
        recipient_info = encap['content']['recipient_infos'][0]

        encryption_algo = recipient_info.chosen['key_encryption_algorithm'].native
        encrypted_key = recipient_info.chosen['encrypted_key'].native

        supported_algos = ['rsaes_pkcs1v15', 'rsa']
        assert encryption_algo['algorithm'] in supported_algos

        plain_key = key.decrypt(
            ciphertext=encrypted_key,
            padding_type='pkcs'
        )

        # Now we have the plain key, we can decrypt the encrypted data
        encrypted_contentinfo = encap['content']['encrypted_content_info']
        logger.debug('encrypted content type is {}'.format(encrypted_contentinfo['content_type'].native))

        algorithm = encrypted_contentinfo['content_encryption_algorithm']  #: EncryptionAlgorithm
        encrypted_content_bytes = encrypted_contentinfo['encrypted_content'].native

        logger.debug('key length is {}'.format(algorithm.key_length))
        logger.debug('cipher is {}'.format(algorithm.encryption_cipher))
        logger.debug('enc mode is {}'.format(algorithm.encryption_mode))

        return decrypt(cipher=algorithm.encryption_cipher, mode=algorithm.encryption_mode, key=plain_key, iv=algorithm.encryption_iv, encrypted_content=encrypted_content_bytes)

    def debug(self):
        logger.debug("SCEP Message")
        logger.debug("------------")
        logger.debug("{:<20}: {}".format('Transaction ID', self.transaction_id))
        logger.debug("{:<20}: {}".format('Message Type', self.message_type))
        logger.debug("{:<20}: {}".format('PKI Status', self.pki_status))

        if self.sender_nonce is not None:
            logger.debug("{:<20}: {}".format('Sender Nonce', b64encode(self.sender_nonce)))
        if self.recipient_nonce is not None:
            logger.debug("{:<20}: {}".format('Recipient Nonce', b64encode(self.recipient_nonce)))

        logger.debug('------------')
        logger.debug('Certificates')
        logger.debug('------------')
        logger.debug('Includes {} attached certificate(s)'.format(len(self.certificates)))
        for c in self.certificates:
            logger.debug(c.subject.human_friendly)

        logger.debug('Signer(s)')
        logger.debug('------------')

        x509name, serial = self.signer
        logger.debug("{:<20}: {}".format('Issuer X.509 Name', x509name))
        # logger.debug("{:<20}: {}".format('Issuer S/N', serial))

        logger.debug("{:<20}: {}".format('Signature Algorithm', self._signer_info['signature_algorithm'].signature_algo))
        logger.debug("{:<20}: {}".format('Digest Algorithm', self._signer_info['digest_algorithm']['algorithm'].native))
