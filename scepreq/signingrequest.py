from asn1crypto import pem, csr, keys as asn1_keys
from asn1crypto.core import PrintableString
from oscrypto import asymmetric
from csrbuilder import CSRBuilder, _pretty_message, _type_name, pem_armor_csr
from certbuilder import CertificateBuilder

from asn1crypto import csr as asn1csr
from asn1crypto import x509 as asn1x509
from asn1crypto import cms as asn1cms
from asn1crypto import core as asn1core
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import serialization

from scepreq.privatekey import PrivateKey
from scepreq.publickey import PublicKey
from scepreq.certificate import Certificate
from cryptography import x509

# # Microsoft-specific OIDs
# PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
# NTDS_CA_SECURITY_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
# NTDS_OBJECTSID = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")
# APPLICATION_POLICIES = x509.ObjectIdentifier("1.3.6.1.4.1.311.21.10")
# SMIME_CAPABILITIES = x509.ObjectIdentifier("1.2.840.113549.1.9.15")
asn1x509.ExtensionId._map.update(
    {
        "1.3.6.1.4.1.311.25.2": "security_ext",
    }
)
asn1x509.ExtensionId._map.update(
    {
        "1.2.840.113549.1.9.15": "smime_capability",
    }
)

asn1x509.Extension._oid_specs.update(
    {
        "security_ext": asn1x509.GeneralNames,
    }
)
# Microsoft-specific ASN.1 OIDs
OID_ENCRYPTED_KEY_HASH = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.21.21")
OID_PRINCIPAL_NAME = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
OID_CMC_ADD_ATTRIBUTES = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.10.10.1")
OID_NTDS_OBJECTSID = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")
SAN_URL_PREFIX = "tag:microsoft.com,2022-09-14:sid:"
class ScepCSRBuilder(CSRBuilder):
    _password = None

    def __init__(self, subject, subject_public_key):
        """
        Unless changed, CSRs will use SHA-256 for the signature

        :param subject:
            An asn1crypto.x509.Name object, or a dict - see the docstring
            for .subject for a list of valid options

        :param subject_public_key:
            An asn1crypto.keys.PublicKeyInfo object containing the public key
            the certificate is being requested for
        """

        self.subject = subject
        self.subject_public_key = subject_public_key
        self.ca = False

        self._hash_algo = 'sha256'
        self._other_extensions = {}

        # Additions for us
        self.alt_sid = None
        self.alt_upn = None
        self.alt_sid_url = None
        self.alt_url = None
        self.alt_dns = None
        self.alt_email = None

    @property
    def password(self):
        """
        A unicode strings representing the authentication password.
        """

        return self._password.native

    @password.setter
    def password(self, value):
        if value == '' or value is None:
            self._password = None
        else:
            self._password = PrintableString(value=value)

    def build(self, signing_private_key):
        """
        Validates the certificate information, constructs an X.509 certificate
        and then signs it

        :param signing_private_key:
            An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
            object for the private key to sign the request with. This should be
            the private key that matches the public key.

        :return:
            An asn1crypto.csr.CertificationRequest object of the request
        """

        is_oscrypto = isinstance(signing_private_key, asymmetric.PrivateKey)
        if not isinstance(signing_private_key, asn1_keys.PrivateKeyInfo) and not is_oscrypto:
            raise TypeError(_pretty_message(
                '''
                signing_private_key must be an instance of
                asn1crypto.keys.PrivateKeyInfo or
                oscrypto.asymmetric.PrivateKey, not %s
                ''',
                _type_name(signing_private_key)
            ))

        signature_algo = signing_private_key.algorithm
        if signature_algo == 'ec':
            signature_algo = 'ecdsa'

        signature_algorithm_id = '%s_%s' % (self._hash_algo, signature_algo)

        def _make_extension(name, value):
            return {
                'extn_id': name,
                'critical': self._determine_critical(name),
                'extn_value': value
            }

        extensions = []
        for name in sorted(self._special_extensions):
            value = getattr(self, '_%s' % name)
            if value is not None:
                extensions.append(_make_extension(name, value))

        for name in sorted(self._other_extensions.keys()):
            extensions.append(_make_extension(name, self._other_extensions[name]))

        attributes = []
        if extensions:
            attributes.append({
                'type': u'extension_request',
                'values': [extensions]
            })

        if self.alt_dns or self.alt_upn or self.alt_sid or self.alt_sid_url or self.alt_email:
            general_names = []

            # Add DNS name
            if self.alt_dns:
                if isinstance(self.alt_dns, bytes):
                    self.alt_dns = self.alt_dns.decode()
                general_names.append(asn1x509.GeneralName({"dns_name": self.alt_dns}))

            if self.alt_email:
                if isinstance(self.alt_dns, bytes):
                    self.alt_dns = self.alt_dns.decode()
                general_names.append(asn1x509.GeneralName({"rfc822_name": self.alt_dns}))


            # Create SAN extension
            san_extension1 = asn1x509.Extension(
                {"extn_id": "subject_alt_name", "extn_value": general_names}
            )
            # Add extension to CSR attributes
            set_of_extensions = asn1csr.SetOfExtensions([[san_extension1]])
            cri_attribute = asn1csr.CRIAttribute(
                {"type": "extension_request", "values": set_of_extensions}
            )
            # attributes.append(cri_attribute)
            # Add UPN
            if self.alt_upn:
                if isinstance(self.alt_upn, bytes):
                    self.alt_upn = self.alt_upn.decode()

                general_names.append(
                    asn1x509.GeneralName(
                        {
                            "other_name": asn1x509.AnotherName(
                                {
                                    "type_id": OID_PRINCIPAL_NAME,
                                    "value": asn1x509.UTF8String(self.alt_upn).retag(
                                        {"explicit": 0}
                                    ),
                                }
                            )
                        }
                    )
                )
            # Add SID URL
            if self.alt_sid_url:
                if isinstance(self.alt_sid_url, bytes):
                    self.alt_sid_url = self.alt_sid_url.decode()

                general_names.append(
                    asn1x509.GeneralName(
                        {"uniform_resource_identifier": f"{SAN_URL_PREFIX}{self.alt_sid_url}"}
                    )
                )

            # Add regular URL
            if self.alt_url:
                if isinstance(self.alt_url, bytes):
                    self.alt_url = self.alt_url.decode()

                general_names.append(
                    asn1x509.GeneralName(
                        {"uniform_resource_identifier": self.alt_url}
                    )
                )

            # Create SAN extension
            san_extension2 = asn1x509.Extension(
                {"extn_id": "subject_alt_name", "extn_value": general_names}
            )

            if self.alt_sid:
                san_extension = asn1x509.Extension(
                    {
                        "extn_id": u"security_ext",
                        "extn_value": [
                            asn1x509.GeneralName(
                                {
                                    "other_name": asn1x509.AnotherName(
                                        {
                                            "type_id": OID_NTDS_OBJECTSID,
                                            "value": asn1x509.OctetString(
                                                self.alt_sid.encode()
                                            ).retag({"explicit": 0}),
                                        }
                                    )
                                }
                            )
                        ],
                    }
                )

            # Add extension to CSR attributes
            set_of_extensions = asn1csr.SetOfExtensions([[san_extension2]])
            cri_attribute = asn1csr.CRIAttribute(
                {"type": "extension_request", "values": set_of_extensions}
            )
            attributes.append(cri_attribute)
            if self.alt_sid:
                # Add extension to CSR attributes
                # this is separate from the names
                set_of_extensions = asn1csr.SetOfExtensions([[san_extension]])
                cri_attribute = asn1csr.CRIAttribute(
                    {"type": "extension_request", "values": set_of_extensions}
                )
                attributes.append(cri_attribute)

        if self._password:
            attributes.append({
                'type': u'challenge_password',
                'values': [self._password]
            })

        certification_request_info = csr.CertificationRequestInfo({
            'version': u'v1',
            'subject': self._subject,
            'subject_pk_info': self._subject_public_key,
            'attributes': attributes
        })

        if signing_private_key.algorithm == 'rsa':
            sign_func = asymmetric.rsa_pkcs1v15_sign
        elif signing_private_key.algorithm == 'dsa':
            sign_func = asymmetric.dsa_sign
        elif signing_private_key.algorithm == 'ec':
            sign_func = asymmetric.ecdsa_sign

        if not is_oscrypto:
            signing_private_key = asymmetric.load_private_key(signing_private_key)
        signature = sign_func(signing_private_key, certification_request_info.dump(), self._hash_algo)

        return csr.CertificationRequest({
            'certification_request_info': certification_request_info,
            'signature_algorithm': {
                'algorithm': signature_algorithm_id,
            },
            'signature': signature
        })

class SigningRequest:
    # @classmethod
    # def generate_pair(cls, key_type='rsa', size=2048):
    #     if key_type == 'rsa':
    #         public_key, private_key = asymmetric.generate_pair('rsa', bit_size=size)
    #     elif key_type == 'dsa':
    #         public_key, private_key = asymmetric.generate_pair('dsa', bit_size=size)
    #     elif key_type == 'ec':
    #         public_key, private_key = asymmetric.generate_pair('ec', bit_size=size, curve=u'secp256r1')
    #     else:
    #         raise ValueError('Unsupported key type ' + key_type)
    #
    #     return PrivateKey(private_key=private_key.asn1)

    @classmethod
    def generate_pair(cls, type='rsa', size=2048):
        if type == 'rsa':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=size,
                backend=default_backend(),
            )
        elif type == 'dsa':
            private_key = dsa.generate_private_key(
                key_size=size,
                backend=default_backend()
            )
        elif type == 'ec':
            private_key = ec.generate_private_key(curve=ec.SECP256R1)
        else:
            raise ValueError('Unsupported key type ' + type)

        der = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return PrivateKey.from_der(der)

    @classmethod
    def generate_csr(cls, dn, key_usage, extended_key_usage, password, private_key=None, alt_dns=None, alt_sid=None, alt_sid_url=None, alt_url=None, alt_email=None, alt_upn=None):
        if private_key is None:
            private_key = cls.generate_pair()

        subject_name = cls.get_subject_from_str(dn)
        name = asn1csr.Name.load(
            subject_name.public_bytes()
        )

        builder = ScepCSRBuilder(
            name,
            private_key.public_key.to_asn1_public_key()
        )
        builder.alt_dns = alt_dns
        builder.alt_upn = alt_upn
        builder.alt_sid = alt_sid
        builder.alt_sid_url = alt_sid_url
        builder.alt_url = alt_url
        builder.alt_email = alt_email
        builder.key_usage = key_usage #[u'digital_signature', u'key_encipherment']

        builder.password = password
        builder.extended_key_usage = set(extended_key_usage)
        # builder.subject_alt_domains = set([u'zomgdevice'])

        request = builder.build(private_key.to_asn1_private_key())

        return SigningRequest(request=request), private_key

    # @classmethod
    # def generate_csr(cls, cn, key_usage, password=None, private_key=None):
    #     """Generate a Certificate Signing Request using a few defaults.
    #
    #     Args:
    #           private_key (rsa.RSAPrivateKey): Optional. If not supplied a key will be generated
    #
    #     Returns:
    #           Tuple of private_key, x509.CertificateSigningRequest
    #     """
    #     if private_key is None:
    #         private_key = cls.generate_pair()
    #
    #     builder = x509.CertificateSigningRequestBuilder()
    #     builder = builder.subject_name(x509.Name([
    #         x509.NameAttribute(NameOID.COMMON_NAME, cn),
    #     ]))
    #     builder = builder.add_extension(
    #         #  Absolutely critical for SCEP
    #         x509.KeyUsage(
    #             digital_signature=True,
    #             content_commitment=False,
    #             key_encipherment=True,
    #             data_encipherment=False,
    #             key_agreement=False,
    #             key_cert_sign=False,
    #             crl_sign=False,
    #             encipher_only=False,
    #             decipher_only=False
    #         ),
    #         True
    #     )
    #
    #     builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(u'1.2.840.113549.1.9.7'), bytes(password)), False)
    #
    #     csr = builder.sign(private_key.to_crypto_private_key(), hashes.SHA512(), default_backend())
    #     der_string = csr.public_bytes(serialization.Encoding.DER)
    #     return SigningRequest(der_string=der_string), private_key

    @classmethod
    def generate_self_signed(cls, cn, key_usage, private_key=None):
        if private_key is None:
            private_key = cls.generate_pair()

        builder = CertificateBuilder(
            {
                u'common_name': cn
            },
            private_key.public_key.to_asn1_public_key()
        )
        builder.key_usage = key_usage #[u'digital_signature', u'key_encipherment']
        builder.self_signed = True
        certificate = builder.build(private_key.to_asn1_private_key())
        return Certificate(certificate=certificate), private_key

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

    def __init__(self, der_string=None, request=None):
        if request is None:
            self._csr = csr.CertificationRequest.load(der_string)
        else:
            self._csr = request

    @property
    def public_key(self):
        return PublicKey(public_key=self._csr[u'certification_request_info'][u'subject_pk_info'])

    def to_der(self):
        return self._csr.dump()

    def to_pem(self):
        return pem_armor_csr(self._csr)

    def to_crypto_csr(self):
        return self._csr

    @staticmethod
    def get_subject_from_str(subject):
        """
        Create a Name object from a subject string.

        Args:
            subject: Subject DN string

        Returns:
            x509.Name object
        """
        return x509.Name(x509.Name.from_rfc4514_string(subject).rdns)