from asn1crypto.algos import DigestAlgorithmId, SignedDigestAlgorithmId
from asn1crypto.core import Sequence, ObjectIdentifier, Integer, Any, OctetString, SetOf, UniversalString, Boolean
from asn1crypto.cms import CMSAttribute, SetOfContentType, SetOfOctetString, SetOfTime, SignerInfos, SetOfContentInfo, \
    SetOfCMSAlgorithmProtection
from asn1crypto.x509 import Name

# asn1crypto defines allowed CMSAttributes in the ``CMSAttributeType`` class.
# however, SCEP uses different OIDs to indicate what kind of request this is.
# TODO: There seems to be no extension mechanism for CMSAttributeType

# keys were actually PrintableString
SCEP_MESSAGE_TYPES = {
    '3': 'cert_rep',
    '17': 'renewal_req',
    '18': 'update_req',
    '19': 'pkcs_req',  # PKCS#10 CSR
    '20': 'cert_poll',
    '21': 'get_cert',
    '22': 'get_crl',
}


class SCEPMessageType(Integer):
    _map = {
        3: 'cert_rep',
        17: 'renewal_req',
        18: 'update_req',
        19: 'pkcs_req',  # PKCS#10 CSR
        20: 'cert_poll',
        21: 'get_cert',
        22: 'get_crl',
    }


class PKIStatus(Integer):
    _map = {
        0: 'granted',
        2: 'rejected',
        3: 'pending'
    }


class FailInfo(Integer):
    _map = {
        0: 'bad_alg',
        1: 'bad_message_check',
        2: 'bad_request',
        3: 'bad_time',
        4: 'bad_cert_id',
    }


class SCEPCMSAttributeType(ObjectIdentifier):
    """Loosely modelled after CMSAttributeType in asn1crypto"""
    _map = {
        # CMSAttributeType
        '1.2.840.113549.1.9.3': u'content_type',
        '1.2.840.113549.1.9.4': u'message_digest',
        '1.2.840.113549.1.9.5': u'signing_time',
        '1.2.840.113549.1.9.6': u'counter_signature',
        '1.2.840.113549.1.9.52': u'algorithm_protection',
        # https://tools.ietf.org/html/rfc3161#page-20
        '1.2.840.113549.1.9.16.2.14': u'signature_time_stamp_token',

        # SCEP Attributes
        '2.16.840.1.113733.1.9.2': u'message_type',
        '2.16.840.1.113733.1.9.3': u'pki_status',
        '2.16.840.1.113733.1.9.4': u'fail_info',
        '2.16.840.1.113733.1.9.5': u'sender_nonce',
        '2.16.840.1.113733.1.9.6': u'recipient_nonce',
        '2.16.840.1.113733.1.9.7': u'transaction_id',
        '2.16.840.1.113733.1.9.8': u'extension_req',
    }


# class CMSAlgorithmProtection(Sequence):
#     _fields = [
#         ('digest_algorithm', DigestAlgorithmId),
#         ('signature_algorithm', SignedDigestAlgorithmId),
#         ('mac_algorithm', )
#     ]
#
# class SetOfCMSAlgorithmProtection(SetOf):
#     _child_spec = CMSAlgorithmProtection

CMSAttribute._oid_specs = {
    'content_type': SetOfContentType,
    'message_digest': SetOfOctetString,
    'signing_time': SetOfTime,
    'counter_signature': SignerInfos,
    'signature_time_stamp_token': SetOfContentInfo,
    'algorithm_protection': SetOfCMSAlgorithmProtection,

    # SCEP
    #'message_type': SCEPMessageType,
    'sender_nonce': SetOfOctetString,
    'recipient_nonce': SetOfOctetString,
    # 'transaction_id': UniversalString,
}


class SCEPPKIMessage(Sequence):
    _fields = [
        ('type', SCEPMessageType),
    ]


class IssuerAndSubject(Sequence):
    _fields = [
        ('issuer', Name),
        ('subject', Name),
    ]
