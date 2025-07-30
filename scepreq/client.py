import logging

import requests
import base64

from asn1crypto.cms import ContentInfo, IssuerAndSerialNumber

from scepreq.builders import PKIMessageBuilder, Signer
from scepreq.certificate import Certificate
from scepreq.crl import RevocationList
from scepreq.cryptoutils import digest_for_data, hex_digest_for_data
from scepreq.envelope import PKCSPKIEnvelopeBuilder
from scepreq.responses import EnrollmentStatus, Capabilities, CACertificates
from scepreq.message import SCEPMessage
from scepreq.enums import CACaps, MessageType, PKIStatus
from scepreq.asn1 import IssuerAndSubject


logger = logging.getLogger(__name__)


class Client:
    def __init__(self, url):
        self.url = url
        self.reverse_cacaps = dict([(cap.value.lower(), cap) for cap in CACaps])

    def get_ca_capabilities(self, identifier=None):
        """Query the SCEP Service for its capabilities."""
        message = ''
        if identifier is not None:
            message = identifier

        res = requests.get(self.url, params={'operation': 'GetCACaps', 'message': message}, verify=False)
        if res.status_code != 200:
            raise ValueError('Got invalid status code for GetCACaps: {}'.format(res.status_code))
        caps = [cap.strip().lower() for cap in res.text.splitlines() if cap.strip()]
        cacaps = {self.reverse_cacaps[cap] for cap in caps if cap in self.reverse_cacaps}
        cacaps_str = [cap.value for cap in cacaps]
        logger.debug('Server Capabilities are ' + ', '.join(cacaps_str))
        return Capabilities(cacaps)

    def get_ca_certs(self, identifier=None):
        """Query the SCEP Service for the CA Certificate."""
        message = ''
        if identifier is not None:
            message = identifier

        res = requests.get(self.url, params={'operation': 'GetCACert', 'message': message}, verify=False)
        if res.status_code != 200:
            raise ValueError('Got invalid status code for GetCACert: {}'.format(res.status_code))
        if res.headers['content-type'] == 'application/x-x509-ca-cert':  # we dont support RA cert yet
            logger.debug('Received response with CA certificates')
            response = CACertificates(certificates=[Certificate.from_der(res.content)])
            assert len(response.certificates) > 0
        elif res.headers['content-type'] == 'application/x-x509-ca-ra-cert':  # intermediate via chain
            logger.debug('Received response with RA certificates')
            msg = SCEPMessage.parse(res.content)
            response = CACertificates(certificates=msg.certificates)
            assert len(response.certificates) > 1
        else:
            raise ValueError('unknown content-type ' + res.headers['content-type'])

        response.verify()

        return response

    def rollover_certificate(self, identifier=None):
        """Query the SCEP Service for rollover certificate"""
        message = ''
        if identifier is not None:
            message = identifier

        #FIXME: ensure that the response is signed by the ca cert received in the get_ca_certs
        ca_certs = self.get_ca_certs(identifier=message)

        res = requests.get(self.url, params={'operation': 'GetNextCACert', 'message': message}, verify=False)
        if res.status_code != 200:
            raise ValueError('Got invalid status code for GetCACert: {}'.format(res.status_code))
        assert res.headers['content-type'] == 'application/x-x509-next-ca-cert'
        msg = SCEPMessage.parse(raw=res.content, signer_cert=ca_certs.signer)
        assert len(msg.certificates) > 0
        return [Certificate.from_der(cert) for cert in msg.certificates]

    def get_cert(self, identity, identity_private_key, serial_number, identifier=None):
        """Perform a GetCert operation by submitting certificate serial number to the SCEP service."""
        cacaps = self.get_ca_capabilities(identifier=identifier)
        ca_certs = self.get_ca_certs(identifier=identifier)

        issuer = ca_certs.issuer.subject
        ias = IssuerAndSerialNumber({'issuer': issuer, 'serial_number': serial_number})
        envelope = PKCSPKIEnvelopeBuilder().encrypt(ias.dump(), cacaps.strongest_cipher())

        return self._pki_operation(identity=identity, identity_private_key=identity_private_key, envelope=envelope, message_type=MessageType.GetCert, cacaps=cacaps, ca_certs=ca_certs)

    def poll(self, identity, identity_private_key, subject, transaction_id, identifier=None):
        """Perform a CertPoll operation by submitting subject and transaction id to the SCEP service."""
        cacaps = self.get_ca_capabilities(identifier=identifier)
        ca_certs = self.get_ca_certs(identifier=identifier)

        issuer = ca_certs.issuer.subject
        ias = IssuerAndSubject({'issuer': issuer, 'subject': subject})
        envelope = PKCSPKIEnvelopeBuilder().encrypt(ias.dump(), cacaps.strongest_cipher())

        return self._pki_operation(identity=identity, identity_private_key=identity_private_key, envelope=envelope, message_type=MessageType.CertPoll, cacaps=cacaps, ca_certs=ca_certs, transaction_id=transaction_id)

    def get_crl(self, identity, identity_private_key, serial_number, identifier=None):
        """Perform a GetCRL operation for given serial number from the SCEP service."""
        cacaps = self.get_ca_capabilities(identifier=identifier)
        ca_certs = self.get_ca_certs(identifier=identifier)

        issuer = ca_certs.issuer.subject
        ias = IssuerAndSerialNumber({'issuer': issuer, 'serial_number': serial_number})
        envelope = PKCSPKIEnvelopeBuilder().encrypt(ias.dump(), cacaps.strongest_cipher())

        return self._pki_operation(identity=identity, identity_private_key=identity_private_key, envelope=envelope, message_type=MessageType.GetCRL, cacaps=cacaps, ca_certs=ca_certs)

    def enrol(self, csr, identity, identity_private_key, identifier=None):
        """Perform a PKCSReq operation by submitting a CSR to the SCEP service."""
        cacaps = self.get_ca_capabilities(identifier=identifier)
        ca_certs = self.get_ca_certs(identifier=identifier)
        envelope = PKCSPKIEnvelopeBuilder().encrypt(csr.to_der(), cacaps.strongest_cipher())
        transaction_id = hex_digest_for_data(data=csr.public_key.to_der(), algorithm='sha1')
        return self._pki_operation(identity=identity, identity_private_key=identity_private_key, envelope=envelope, message_type=MessageType.PKCSReq, cacaps=cacaps, ca_certs=ca_certs, transaction_id=transaction_id)

    def _pki_operation(self, identity, identity_private_key, envelope, message_type, cacaps, ca_certs, transaction_id=None):
        """Perform a PKIOperation using the PKI Envelope given."""
        envelope = envelope.add_recipient(ca_certs.recipient)

        envelope, key, iv = envelope.finalize()

        signer = Signer(identity, identity_private_key, cacaps.strongest_signature_algorithm())

        pki_msg_builder = PKIMessageBuilder().message_type(
            message_type
        ).pki_envelope(
            envelope
        ).add_signer(
            signer
        ).transaction_id(
            transaction_id
        ).sender_nonce()

        pki_msg = pki_msg_builder.finalize(digest_algorithm=cacaps.strongest_message_digest())

        res = self.__pki_operation(data=pki_msg.dump(), cacaps=cacaps)

        cert_rep = SCEPMessage.parse(raw=res.content, signer_cert=ca_certs.signer)
        cert_rep.debug()
        if cert_rep.pki_status == PKIStatus.FAILURE:
            return EnrollmentStatus(fail_info=cert_rep.fail_info)
        elif cert_rep.pki_status == PKIStatus.PENDING:
            return EnrollmentStatus(transaction_id=cert_rep.transaction_id)
        else:
            decrypted_bytes = cert_rep.get_decrypted_envelope_data(identity, identity_private_key)
            degenerate_info = ContentInfo.load(decrypted_bytes)
            assert degenerate_info['content_type'].native == 'signed_data'
            signed_response = degenerate_info['content']

            certificates = None
            revocation_list = None

            if (message_type is MessageType.PKCSReq) or (message_type is MessageType.GetCert) or (message_type is MessageType.CertPoll):
                certs = signed_response['certificates']
                certificates = [Certificate(der_string=cert.chosen.dump()) for cert in certs]
                for c in certificates:
                    logger.debug("Cert was issued with subject: %s", c.subject.human_friendly)
            elif message_type is MessageType.GetCRL:
                crls = signed_response['crls']
                received_crl = crls[0].chosen
                revocation_list = RevocationList(revocation_list=received_crl)

            return EnrollmentStatus(certificates=certificates, crl=revocation_list)

    def __pki_operation(self, data, cacaps):
        """Perform a PKIOperation using the CMS data given."""
        headers = {'content-type': 'application/x-pki-message'}
        if cacaps.contains(CACaps.POSTPKIOperation):
            res = requests.post(self.url, params={'operation': 'PKIOperation', 'message': ''}, data=data, headers=headers, verify=False)
        else:
            b64_bytes = base64.b64encode(data)
            b64_string = b64_bytes.encode('ascii')
            res = requests.get(self.url, params={'operation': 'PKIOperation', 'message': b64_string}, data=data, headers=headers, verify=False)

        if res.status_code != 200:
            raise ValueError('Got invalid status code for PKIOperation: {}'.format(res.status_code))

        return res
