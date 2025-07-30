import os
import logging
from base64 import b64encode
from uuid import uuid4

from asn1crypto.core import PrintableString
from asn1crypto.cms import CMSAttribute, ContentInfo, EnvelopedData, SignedData, SignerInfos, \
    SignerInfo, CMSAttributes, SignerIdentifier, IssuerAndSerialNumber, OctetString, CertificateSet, \
    CertificateChoices, ContentType, DigestAlgorithms, CMSVersion, RevocationInfoChoices
from asn1crypto.algos import DigestAlgorithm, SignedDigestAlgorithm, SignedDigestAlgorithmId, DigestAlgorithmId

from scepreq.cryptoutils import digest_for_data
from scepreq.enums import MessageType, PKIStatus, FailInfo
from scepreq.asn1 import SCEPCMSAttributeType
from scepreq.certificate import Certificate


CMSAttribute._fields = [
    ('type', SCEPCMSAttributeType),
    ('values', None),
]

logger = logging.getLogger(__name__)

def create_degenerate_pkcs7(*certificates):
    """Produce a PKCS#7 Degenerate case.

    The degenerate case is a SignedData content type in which there are no signers. Certificates are disseminated
    via the ``certificates`` attribute.

    Args:
         *certificates (List[x509.Certificate]): The certificates to attach to the degenerate pkcs#7 payload.
            The first must always be the issued certificate.
    Returns:
          ContentInfo: The ContentInfo containing a SignedData structure.
    """
    certificates_asn1 = [certificate.to_asn1_certificate() for certificate in certificates]

    # draft-gutmann-scep 3.4. content type must be omitted
    empty = ContentInfo({
        'content_type': ContentType('data')
    })

    sd_certificates = CertificateSet([CertificateChoices('certificate', asn1) for asn1 in certificates_asn1])

    sd = SignedData({
        'version': CMSVersion(1),
        'encap_content_info': empty,
        'digest_algorithms': DigestAlgorithms([]),
        'certificates': sd_certificates,
        'signer_infos': SignerInfos([]),
        'crls': RevocationInfoChoices([]),
    })

    return ContentInfo({
        'content_type': ContentType('signed_data'),
        'content': sd,
    })


class Signer(object):
    """The signer object represents a single signer on a SignedData structure.

    It provides a convenient way of generating a signature and a SignerInfo.

    Attributes:
          certificate (x509.Certificate): Signers certificate
          private_key (rsa.RSAPrivateKey): Signers private key
    """


    def __init__(self,
                 certificate,
                 private_key,
                 digest_algorithm,
                 signed_attributes=None):

        self.certificate = certificate
        self.private_key = private_key

        # self.digest_algorithm_id = DigestAlgorithmId('sha512')
        self.digest_algorithm_id = {
            'sha1': DigestAlgorithmId(u'sha1'),
            'sha256': DigestAlgorithmId(u'sha256'),
            'sha512': DigestAlgorithmId(u'sha512'),
        }[digest_algorithm]
        self.digest_algorithm = DigestAlgorithm({'algorithm': self.digest_algorithm_id})

        self.signed_digest_algorithm_id = SignedDigestAlgorithmId(u'rsassa_pkcs1v15')  # was: sha256_rsa
        self.signed_digest_algorithm = SignedDigestAlgorithm({'algorithm': self.signed_digest_algorithm_id})

        if signed_attributes is not None:
            self.signed_attributes = signed_attributes
        else:
            self.signed_attributes = []

    @property
    def sid(self):
        """Get a SignerIdentifier for IssuerAndSerialNumber"""
        asn1cert = self.certificate.to_asn1_certificate()

        # Signer Identifier
        ias = IssuerAndSerialNumber({'issuer': asn1cert.issuer, 'serial_number': asn1cert.serial_number})
        sid = SignerIdentifier('issuer_and_serial_number', ias)
        return sid

    def sign(self,
             data,
             content_type,
             content_digest,
             cms_attributes):
        """Generate a signature encrypted with the signer's private key and return the SignerInfo."""

        # The CMS standard requires that the content-type authenticatedAttribute and the message-digest
        # attribute must be present if any authenticatedAttribute exists at all.
        self.signed_attributes = cms_attributes

        # NDES does not even include this
        # self.signed_attributes.insert(0, CMSAttribute({
        #     'type': 'signing_time',
        #     'values': [GeneralizedTime(datetime.datetime.utcnow())]
        # }))

        self.signed_attributes.insert(0, CMSAttribute({
            'type': u'message_digest',
            'values': [OctetString(content_digest)],
        }))

        # This refers to whatever the content of EncapsulatedContentInfo is
        self.signed_attributes.insert(0, CMSAttribute({
            'type': u'content_type',
            'values': [content_type],
        }))

        cms_attributes = CMSAttributes(self.signed_attributes)

        # NOTE: no need to calculate this digest as .signer() does the hashing

        # RFC5652
        # The message digest is
        # computed on either the content being signed or the content
        # together with the signed attributes using the process described in
        # Section 5.4.
        # digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

        # the initial input is the encapContentInfo eContent OCTET STRING
        # RFC5652 Section 5.4 - When the field (signed_attrs) is present, however, the result is the message
        # digest of the complete DER encoding of the SignedAttrs value
        # contained in the signedAttrs field.
        # NOTE: it is not clear whether data is included
        #digest.update(data)
        # digest.update(cms_attributes.dump())
        # d = digest.finalize()

        # Make DigestInfo from result
        # NOTE: It is not clear whether this applies: RFC5652 - Section 5.5.
        # digest_info = DigestInfo({
        #     'digest_algorithm': self.digest_algorithm,
        #     'digest': d,
        # })

        signature = self.private_key.sign(
            data=cms_attributes.dump(),
            padding_type='pkcs',
            algorithm=self.digest_algorithm_id.native
        )

        signer_info = SignerInfo({
            # Version must be 1 if signer uses IssuerAndSerialNumber as sid
            'version': CMSVersion(1),
            'sid': self.sid,

            'digest_algorithm': self.digest_algorithm,
            'signed_attrs': cms_attributes,

            # Referred to as ``digestEncryptionAlgorithm`` in the RFC
            'signature_algorithm': self.signed_digest_algorithm,

            # Referred to as ``encryptedDigest`` in the RFC
            'signature': OctetString(signature),
        })

        return signer_info


class PKIMessageBuilder(object):
    """The PKIMessageBuilder builds pkiMessages as defined in the SCEP RFC.

    Attributes:
          _signers: List of signers to create signatures and populate signerinfos.
          _cms_attributes: List of CMSAttribute
          _certificates: List of Certificates
          _pki_envelope: The enveloped data being signed

    See Also:
          - `<https://tools.ietf.org/html/draft-nourse-scep-23#section-3.1>`_.
    """

    def __init__(self):
        self._signers = []
        self._cms_attributes = []
        self._certificates = None
        self._pki_envelope = None
        self._certificates = CertificateSet()

    def certificates(self, *certificates):
        """Add x.509 certificates to be attached to the certificates field.

        Args:
              certificates: variadic argument of x509.Certificate
        Returns:
              PKIMessageBuilder: This instance
        See Also:
              - `pkcs#7 RFC 2315 Section 9.1 <https://tools.ietf.org/html/rfc2315#section-9.1>`_.
        """
        for cert in certificates:
            choice = CertificateChoices('certificate', cert.to_asn1_certificate())
            self._certificates.append(choice)

        return self

    def add_signer(self, signer):
        """Add a signer to SignerInfos.

        Args:
              signer (Signer): Signer instance
        Returns:
              PKIMessageBuilder: This instance
        See Also:
              - `pkcs#7 RFC2315 Section 9.2 <https://tools.ietf.org/html/rfc2315#section-9.2>`_.
        """
        self._signers.append(signer)
        self._certificates.append(CertificateChoices('certificate', signer.certificate.to_asn1_certificate()))

        return self

    def message_type(self, message_type):
        """Set the SCEP Message Type Attribute.

        Args:
              message_type (MessageType): A valid PKIMessage messageType
        Returns:
              PKIMessageBuilder: This instance
        See Also:
              - `draft-gutmann-scep Section 3.2.1.2.
                <https://datatracker.ietf.org/doc/draft-gutmann-scep/?include_text=1>`_.
        """
        attr = CMSAttribute({
            'type': u'message_type',
            'values': [PrintableString(message_type.value)]
        })

        logger.debug("{:<20}: {}".format('Message Type', message_type.value))

        self._cms_attributes.append(attr)

        return self

    def pki_envelope(self, envelope):
        """Set content for encryption inside the pkcsPKIEnvelope

        Args:
            envelope (EnvelopedData): The pkcsPKIEnvelope

        Returns:
            PKIMessageBuilder: This instance
        """
        self._pki_envelope = envelope

        return self

    def pki_status(self, status, failure_info=None):
        """Set the PKI status of the operation.

        Args:
              status (PKIStatus): A valid pkiStatus value
              failure_info (FailInfo): A failure info type, which must be present if PKIStatus is failure.
        Returns:
              PKIMessageBuilder: This instance
        See Also:
              - `draft-gutmann-scep Section 3.2.1.3.
                <https://datatracker.ietf.org/doc/draft-gutmann-scep/?include_text=1>`_.
        """
        attr = CMSAttribute({
            'type': 'pki_status',
            'values': [PrintableString(status.value)],
        })
        self._cms_attributes.append(attr)

        logger.debug("{:<20}: {}".format('PKI Status', status.value))

        if status == PKIStatus.FAILURE:
            if failure_info is None:
                raise ValueError('You cannot specify failure without failure info')

            fail_attr = CMSAttribute({
                'type': 'fail_info',
                'values': [PrintableString(failure_info.value)],
            })

            logger.debug("{:<20}: {}".format('Failure Info', failure_info.value))

            self._cms_attributes.append(fail_attr)

        return self

    def sender_nonce(self, nonce=None):
        """Add a sender nonce.

        Args:
              nonce (bytes or OctetString): Sender nonce
        Returns:
              PKIMessageBuilder: This instance
        See Also:
              - `draft-gutmann-scep Section 3.2.1.5.
                <https://datatracker.ietf.org/doc/draft-gutmann-scep/?include_text=1>`_.
        """
        if isinstance(nonce, bytes):
            nonce = OctetString(nonce)
        elif nonce is None:
            nonce = OctetString(os.urandom(16))

        attr = CMSAttribute({
            'type': u'sender_nonce',
            'values': [nonce],
        })

        logger.debug("{:<20}: {}".format('Sender Nonce', b64encode(nonce.native)))

        self._cms_attributes.append(attr)
        return self

    def recipient_nonce(self, nonce):
        """Add a recipient nonce.

        Args:
              nonce (bytes or OctetString): Recipient nonce
        Returns:
              PKIMessageBuilder: This instance
        See Also:
              - `draft-gutmann-scep Section 3.2.1.5.
                <https://datatracker.ietf.org/doc/draft-gutmann-scep/?include_text=1>`_.
        """
        if isinstance(nonce, bytes):
            nonce = OctetString(nonce)

        attr = CMSAttribute({
            'type': u'recipient_nonce',
            'values': [nonce],
        })

        logger.debug("{:<20}: {}".format('Recipient Nonce', b64encode(nonce.native)))

        self._cms_attributes.append(attr)
        return self

    def transaction_id(self, trans_id=None):
        """Add a transaction ID.

        Args:
              trans_id (str or PrintableString): Transaction ID. If omitted, one is generated
        Returns:
              PKIMessageBuilder: This instance
        See Also:
              - `draft-gutmann-scep Section 3.2.1.1.
                <https://datatracker.ietf.org/doc/draft-gutmann-scep/?include_text=1>`_.
        """
        if isinstance(trans_id, str):
            trans_id = PrintableString(trans_id)
        elif trans_id is None:
            trans_id = PrintableString(str(uuid4()))

        attr = CMSAttribute({
            'type': u'transaction_id',
            'values': [trans_id]
        })

        logger.debug("{:<20}: {}".format('Transaction ID', trans_id))

        self._cms_attributes.append(attr)
        return self

    def _build_cmsattributes(self):
        """Finalize the set of CMS Attributes and return the collection.

        Returns:
              CMSAttributes: All of the added CMS attributes
        """
        return CMSAttributes(value=self._cms_attributes)

    def _build_signerinfos(self, content, content_digest, cms_attributes):
        """Build all signer infos and return a collection.

        Returns:
            SignerInfos: all signers
        """
        return SignerInfos(signer.sign(content, ContentType(u'data'), content_digest, cms_attributes) for signer in self._signers)

    def finalize(self, digest_algorithm):
        """Build all data structures from the given parameters and return the top level contentInfo.

        Returns:
              ContentInfo: The PKIMessage
        """
        pkcs_pki_envelope = self._pki_envelope

        pkienvelope_content_info = ContentInfo({
            'content_type': ContentType(u'enveloped_data'),
            'content': pkcs_pki_envelope,
        })

        # NOTE: This might not be needed for the degenerate CertRep
        encap_info = ContentInfo({
            'content_type': ContentType(u'data'),
            'content': pkienvelope_content_info.dump()
        })

        # Calculate digest on encrypted content + signed_attrs
        d = digest_for_data(algorithm=digest_algorithm, data=pkienvelope_content_info.dump())

        # Now start building SignedData
        signer_infos = self._build_signerinfos(pkienvelope_content_info.dump(), d, self._cms_attributes)

        certificates = self._certificates

        da_id = DigestAlgorithmId(digest_algorithm)
        da = DigestAlgorithm({u'algorithm': da_id})
        das = DigestAlgorithms([da])

        sd = SignedData({
            'version': 1,
            'certificates': certificates,
            'signer_infos': signer_infos,
            'digest_algorithms': das,
            'encap_content_info': encap_info,  # should point to type data + content contentinfo
        })

        ci = ContentInfo({
            'content_type': ContentType(u'signed_data'),
            'content': sd,
        })

        return ci

