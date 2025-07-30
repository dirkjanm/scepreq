# scepreq 

![Python 3 only](https://img.shields.io/badge/python-3.7+-blue.svg)
![License: MIT](https://img.shields.io/pypi/l/scepreq.svg)
![PyPI version](https://img.shields.io/pypi/v/scepreq.svg)

scepreq is a tool that is intended to talk with AD CS NDES servers over the SCEP protocol to request certificates. For information on the use cases and examples, see the [release blog](https://dirkjanm.io/extending-ad-cs-attack-surface-intune-certs/).

It can be installed via pypi with `pip install scepreq` or with an installer such as pip after cloning the GitHub repository with `pip install .`.

```
(scepreq) ➜  scepreq git:(main) ✗ scepreq -h
usage: scepreq [-h] -u URL [--output-cert OUTPUT_CERT] [--output-key OUTPUT_KEY] [--output-csr OUTPUT_CSR] -s SUBJECT [--key-usage KEY_USAGE]
               [--extended-key-usage EXTENDED_KEY_USAGE] [--key-length KEY_LENGTH] [--hash-algorithm {sha1,sha256,sha384,sha512}] -p PASSWORD [--dns DNS]
               [--upn UPN] [--sid SID] [--sid-url SID_URL] [--email EMAIL] [-v]

SCEP Client for certificate enrollment

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     SCEP server URL (e.g., https://server/certsrv/mscep/mscep.dll) (default: None)
  --output-cert OUTPUT_CERT
                        Output certificate file path (default: cert.crt)
  --output-key OUTPUT_KEY
                        Output private key file path (default: cert.key)
  --output-csr OUTPUT_CSR
                        Output CSR file path (default: cert.csr)
  -s SUBJECT, --subject SUBJECT
                        Subject DN for the certificate as specified by the template (default: None)
  --key-usage KEY_USAGE
                        Key usage, comma-separated (e.g., digital_signature,key_encipherment) (default: digital_signature,key_encipherment)
  --extended-key-usage EXTENDED_KEY_USAGE, --eku EXTENDED_KEY_USAGE
                        Extended Key Usage, comma-separated. Can use OIDs or friendly names: client_auth, server_auth, code_signing, secure_email, time_stamping,
                        ocsp_signing, smart_card_logon, ipsec_ike, document_signing, any_purpose (default: client_auth)
  --key-length KEY_LENGTH
                        RSA key length in bits (default: 2048)
  --hash-algorithm {sha1,sha256,sha384,sha512}
                        Hash algorithm to use (default: sha256)
  -p PASSWORD, --password PASSWORD
                        SCEP request password (default: None)
  --dns DNS             DNS Subject Alternative Name (default: None)
  --upn UPN             UPN Subject Alternative Name (default: None)
  --sid SID             SID for Subject Alternative Name (added as AD SID security extension) (default: None)
  --sid-url SID_URL     SID URL for Subject Alternative Name (added as tag:microsoft.com,2022-09-14:sid:<sid> URL, used for strong mapping) (default: None)
  --email EMAIL         Email address for Subject Alternative Name (default: None)
  -v, --verbose         Enable debug logging (default: False)
```

**Note**: this is not a tool intended for usage outside of pentesting / security validation purposes. For example, the tool does not validate TLS certificates or the signature of all messages.