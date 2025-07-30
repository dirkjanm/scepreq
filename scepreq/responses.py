from cryptography.hazmat.primitives.asymmetric import padding

from scepreq.enums import CACaps, PKIStatus


class Capabilities:
    def __init__(self, caps):
        self.caps = caps

    def contains(self, capability):
        return self.caps.__contains__(capability)

    def is_post_supported(self):
        return self.contains(CACaps.POSTPKIOperation)

    def is_rollover_supported(self):
        return self.contains(CACaps.GetNextCACert)

    def is_renewal_supported(self):
        return self.contains(CACaps.Renewal)

    def is_update_supported(self):
        return self.contains(CACaps.Update)

    def strongest_cipher(self):
        if self.contains(CACaps.AES):
            if self.contains(CACaps.SHA256):
                return 'aes256'
            else:
                return 'aes128'
        else:
            return '3des'

    def strongest_message_digest(self):
        if self.contains(CACaps.SHA512):
            return 'sha512'
        elif self.contains(CACaps.SHA256):
            return 'sha256'
        elif self.contains(CACaps.SHA1):
            return 'sha1'
        else:
            return 'md5'

    def strongest_signature_algorithm(self):
        if self.contains(CACaps.SHA512):
            return 'sha512'
        elif self.contains(CACaps.SHA256):
            return 'sha256'
        elif self.contains(CACaps.SHA1):
            return 'sha1'
        else:
            return 'md5'


class CACertificates:
    def __init__(self, certificates):
        self._certificates = certificates

        self._recipient = self.__recipient()
        self._signer = self.__signer()
        self._issuer = self.__issuer()

    @property
    def certificates(self):
        return self._certificates

    def verify(self):
        assert self.issuer is not None
        assert self.signer is not None
        assert self.recipient is not None

        try:
            if self.issuer != self.recipient:
                self.issuer.to_crypto_certificate().public_key().verify(
                    self.recipient.to_crypto_certificate().signature,
                    self.recipient.to_crypto_certificate().tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    self.recipient.to_crypto_certificate().signature_hash_algorithm
                )
        except Exception as e:
            raise Exception('RA is not issued by CA')

        try:
            if self.issuer != self.signer:
                self.issuer.to_crypto_certificate().public_key().verify(
                    self.signer.to_crypto_certificate().signature,
                    self.signer.to_crypto_certificate().tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    self.signer.to_crypto_certificate().signature_hash_algorithm
                )
        except Exception as e:
            raise Exception('RA is not issued by CA')

    @property
    def signer(self):
        return self._signer

    def __signer(self):
        required = set(['digital_signature'])
        not_required = set()
        digital_sign = self._filter(required_key_usage=required, not_required_key_usage=not_required, ca_only=False)
        if len(digital_sign) > 0:
            return digital_sign[0]

        ca = self._filter(required_key_usage=set(), not_required_key_usage=set(), ca_only=True)
        if len(ca) > 0:
            return ca[0]

        return None

    @property
    def issuer(self):
        return self._issuer

    def __issuer(self):
        ca = self._filter(required_key_usage=set(), not_required_key_usage=set(), ca_only=True)
        expected = self.recipient.issuer
        for cert in ca:
            if cert.subject == expected:
                return cert

        if ca[0] == self.recipient:
            return cert

        return None

    @property
    def recipient(self):
        return self._recipient

    def __recipient(self):
        required = set(['key_encipherment'])
        not_required = set(['digital_signature', 'non_repudiation', 'data_encipherment'])
        key_enc = self._filter(required_key_usage=required, not_required_key_usage=not_required, ca_only=False)
        if len(key_enc) > 0:
            return key_enc[0]

        required = set(['data_encipherment'])
        not_required = set(['digital_signature', 'non_repudiation', 'key_encipherment'])
        data_enc = self._filter(required_key_usage=required, not_required_key_usage=not_required, ca_only=False)
        if len(data_enc) > 0:
            return data_enc[0]

        ca = self._filter(required_key_usage=set(), not_required_key_usage=set(), ca_only=True)
        if len(ca) > 0:
            return ca[0]

        return None

    def _filter(self, required_key_usage, not_required_key_usage, ca_only=False):
        matching_certificates = list()
        for cert in self._certificates:
            if bool(cert.is_ca) != ca_only:
                continue

            # Having the key_usage field can be optional.
            # ref: https://security.stackexchange.com/questions/68491/recommended-key-usage-for-a-client-certificate
            # ref: https://docs.digicert.com/en/trust-lifecycle-manager/certificates/certificate-attributes-and-extensions/key-usage.html
            if cert.key_usage and (required_key_usage.intersection(cert.key_usage) != required_key_usage or
                                   not_required_key_usage.difference(cert.key_usage) != not_required_key_usage):
                continue

            matching_certificates.append(cert)
        return matching_certificates


class EnrollmentStatus:
    def __init__(self, fail_info=None, transaction_id=None, certificates=None, crl=None):
        if fail_info:
            self.status = PKIStatus.FAILURE
            self.fail_info = fail_info
        elif transaction_id:
            self.status = PKIStatus.PENDING
            self.transaction_id = transaction_id
        else:
            self.status = PKIStatus.SUCCESS
            self.certificates = certificates
            self.crl = crl
