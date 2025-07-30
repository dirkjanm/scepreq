from enum import Enum, IntEnum

class MessageType(Enum):
    """The SCEP Message Type.

    This is encoded as PrintableString so this enum also uses strings.

    See Also:
        - `SCEP RFC <https://datatracker.ietf.org/doc/draft-gutmann-scep/?include_text=1>`_ Section 3.2.1.2.
    """
    CertRep = '3'
    """Response to certificate or CRL request"""

    RenewalReq = '17'
    """PKCS #10 certificate request for renewal of
      an existing certificate."""

    UpdateReq = '18'
    """PKCS #10 certificate request for update of a
      certificate issued by a different CA."""

    PKCSReq = '19'
    """PKCS #10 certificate request."""

    CertPoll = '20'
    """Certificate polling in manual enrolment."""

    GetCert = '21'
    """Retrieve a certificate."""

    GetCRL = '22'
    """Retrieve a CRL."""


class PKIStatus(Enum):
    """The SCEP PKI Status

    Decimal value as printableString

    See Also:
        - SCEP RFC Section 3.2.1.3.
    """
    SUCCESS = '0'
    FAILURE = '2'
    PENDING = '3'


class FailInfo(Enum):
    """SCEP Failure Information"""
    BadAlg = '0'
    """Unrecognized or unsupported algorithm."""

    BadMessageCheck = '1'
    """Integrity check (meaning signature
      verification of the CMS message) failed."""

    BadRequest = '2'
    """Transaction not permitted or supported."""

    BadTime = '3'
    """The signingTime attribute from the CMS
      authenticatedAttributes was not sufficiently close to the system
      time (this failure code is present for legacy reasons and is
      unlikely to be encountered in practice)."""

    BadCertId = '4'
    """No certificate could be identified matching the
      provided criteria."""


class CACaps(Enum):
    """CA Capabilities"""
    AES = 'AES'
    DES3 = 'DES3'
    GetNextCACert = 'GetNextCACert'
    POSTPKIOperation = 'POSTPKIOperation'
    Renewal = 'Renewal'
    SHA1 = 'SHA-1'
    SHA256 = 'SHA-256'
    SHA512 = 'SHA-512'
    SCEPStandard = 'SCEPStandard'
    Update = 'Update'


class RevocationReason(IntEnum):
    """RFC 5280 - Reasons for Certificate Revocation

    See Also:
          - `https://tools.ietf.org/html/rfc5280`_.
    """
    unspecified = 0
    key_compromise = 1
    ca_compromise = 2
    affiliation_changed = 3
    superseded = 4
    cessation_of_operation = 5
    certificate_hold = 6
    remove_from_crl = 8
    privilege_withdrawn = 9
    aa_compromise = 10

