#!/usr/bin/env python3
from scepreq.client import Client
from scepreq.signingrequest import SigningRequest
import logging
import argparse
import sys
import warnings
import urllib3
from typing import Dict, Set, List, Optional
from scepreq.enums import PKIStatus, FailInfo
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# EKU OID mappings for common usages
EKU_MAPPINGS = {
    'client_auth': '1.3.6.1.5.5.7.3.2',
    'server_auth': '1.3.6.1.5.5.7.3.1',
    'code_signing': '1.3.6.1.5.5.7.3.3',
    'secure_email': '1.3.6.1.5.5.7.3.4',
    'time_stamping': '1.3.6.1.5.5.7.3.8',
    'ocsp_signing': '1.3.6.1.5.5.7.3.9',
    'smart_card_logon': '1.3.6.1.4.1.311.20.2.2',
    'ipsec_ike': '1.3.6.1.5.5.7.3.17',
    'document_signing': '1.3.6.1.4.1.311.10.3.12',
    'any_purpose': '2.5.29.37.0',
}

def parse_key_usage(key_usage_str: str) -> Set[str]:
    """Parse key usage string into a set of key usage values."""
    if not key_usage_str:
        return set()
    return {ku.strip() for ku in key_usage_str.split(',')}

def parse_extended_key_usage(eku_str: str) -> List[str]:
    """Parse extended key usage string into a list of OIDs."""
    if not eku_str:
        return []
    
    ekus = []
    for eku in eku_str.split(','):
        eku = eku.strip()
        # If it's a known mapping, replace with OID
        if eku in EKU_MAPPINGS:
            ekus.append(EKU_MAPPINGS[eku])
        else:
            # Assume it's already an OID or custom value
            ekus.append(eku)
    return ekus

def setup_argparse() -> argparse.Namespace:
    """Setup argument parser for the SCEP client."""
    parser = argparse.ArgumentParser(
        description='SCEP Client for certificate enrollment',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # SCEP server URL
    parser.add_argument('-u', '--url', required=True,
                        help='SCEP server URL (e.g., https://server/certsrv/mscep/mscep.dll)')
    
    # Certificate and key output options
    parser.add_argument('--output-cert', default='cert.crt',
                        help='Output certificate file path')
    parser.add_argument('--output-key', default='cert.key',
                        help='Output private key file path')
    parser.add_argument('--output-csr', default='cert.csr',
                        help='Output CSR file path')
    
    # Common Name and Subject
    parser.add_argument('-s', '--subject', required=True,
                        help='Subject DN for the certificate as specified by the template')
    
    # Key usage
    parser.add_argument('--key-usage', default='digital_signature,key_encipherment',
                        help='Key usage, comma-separated (e.g., digital_signature,key_encipherment)')
    
    # Extended key usage
    parser.add_argument('--extended-key-usage', '--eku', 
                        help='Extended Key Usage, comma-separated. Can use OIDs or friendly names: ' + 
                             ', '.join(EKU_MAPPINGS.keys()), default='client_auth')
    
    # Key parameters
    parser.add_argument('--key-length', type=int, default=2048,
                        help='RSA key length in bits')
    parser.add_argument('--hash-algorithm', choices=['sha1', 'sha256', 'sha384', 'sha512'], 
                        default='sha256', help='Hash algorithm to use')
    
    # Password for private key
    parser.add_argument('-p', '--password', required=True,
                        help='SCEP request password')
    
    # Subject Alternative Name parameters
    parser.add_argument('--dns', 
                        help='DNS Subject Alternative Name')
    parser.add_argument('--upn', 
                        help='UPN Subject Alternative Name')
    parser.add_argument('--sid', 
                        help='SID for Subject Alternative Name (added as AD SID security extension)')
    parser.add_argument('--sid-url', 
                        help='SID URL for Subject Alternative Name (added as tag:microsoft.com,2022-09-14:sid:<sid> URL, used for strong mapping)')
    parser.add_argument('--url', 
                        help='URL Subject Alternative Name')
    parser.add_argument('--email', 
                        help='Email address for Subject Alternative Name')
    
    # Logging
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable debug logging')
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
        return
    return parser.parse_args()

def main():
    args = setup_argparse()
    
    # Configure logging
    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    
    logging.basicConfig(level=log_level)
    logger = logging.getLogger(__name__)
    
    # Initialize SCEP client
    logger.info(f"Connecting to SCEP server: {args.url}")
    client = Client(args.url)
    
    # Get CA capabilities
    capabilities = client.get_ca_capabilities()
    logger.debug(f"CA Capabilities: {capabilities}")
    
    # Parse key usage and extended key usage
    key_usage = parse_key_usage(args.key_usage)
    extended_key_usage = parse_extended_key_usage(args.extended_key_usage)
    
    # Generate self-signed identity certificate
    identity, identity_private_key = SigningRequest.generate_self_signed(
        cn='5d635756-72a8-4945-8b32-37e85681c964',
        key_usage={'digital_signature', 'key_encipherment'}
    )
    
    # Generate CSR
    logger.info(f"Generating CSR with CN: {args.subject}")
    private_key =  SigningRequest.generate_pair(size=int(args.key_length))
    csr, private_key = SigningRequest.generate_csr(args.subject, key_usage, extended_key_usage, args.password, private_key, alt_dns=args.dns, alt_sid=args.sid, alt_sid_url=args.sid_url, alt_email=args.email, alt_upn=args.upn)
    
    # Save CSR
    logger.info(f"Saving CSR to {args.output_csr}")
    with open(args.output_csr, 'wb') as outfile:
        outfile.write(csr.to_pem())
    
    # Save private key
    logger.info(f"Saving private key to {args.output_key}")
    with open(args.output_key, 'wb') as outfile:
        outfile.write(private_key.to_pem())
    
    # Enroll with SCEP server
    logger.info("Enrolling with SCEP server")
    res = client.enrol(
        csr=csr,
        identity=identity, 
        identity_private_key=identity_private_key
    )
    if res.status == PKIStatus.SUCCESS:
        logger.info("Enrollment result: SUCCESS")
    else:
        logger.error(f"Enrollment result: failed :( with status: {FailInfo(res.fail_info).name}")
        return 1
    
    if res.certificates:
        logger.info(f"Saving certificate to {args.output_cert}")
        with open(args.output_cert, 'wb') as outfile:
            outfile.write(res.certificates[0].to_pem())
        logger.info("Certificate successfully saved")
    else:
        logger.error("No certificates received from server")
        return 1
            
    
    return 0

if __name__ == "__main__":
    main()