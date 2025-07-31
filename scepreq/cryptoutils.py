import hashlib

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ModuleNotFoundError:
    # Older cryptography versions
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7


def digest_function_for_type(algorithm):
    digest_function = {
        'sha1': hashes.SHA1,  # macOS
        'sha256': hashes.SHA256,
        'sha512': hashes.SHA512
    }[algorithm]

    return digest_function


def digest_for_data(algorithm, data):
    digest_function = digest_function_for_type(algorithm=algorithm)

    digest = hashes.Hash(digest_function(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def hex_digest_for_data(algorithm, data):
    digest_function = {
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'md5': hashlib.md5
    }[algorithm]
    return digest_function(data).hexdigest()


def padding_for_type(padding_type, hash_algo=hashes.SHA256, mgf=padding.MGF1, label=None):
    if padding_type == 'pkcs':
        return padding.PKCS1v15()
    elif padding_type == 'pss':
        return padding.PSS(mgf=mgf(hash_algo), salt_length=hash_algo.digest_size)
    elif padding_type == 'oaep':
        return padding.OAEP(mgf=mgf(hash_algo), algorithm=hash_algo, label=label)
    else:
        raise ValueError('Unknown padding type ' + padding)


def mode_for_type(mode_type, iv_or_tweak=None):
    if mode_type == 'cbc':
        return modes.CBC(initialization_vector=iv_or_tweak)
    elif mode_type == 'xts':
        return modes.XTS(tweak=iv_or_tweak)
    elif mode_type == 'ecb':
        return modes.ECB()
    elif mode_type == 'ofb':
        return modes.OFB(initialization_vector=iv_or_tweak)
    elif mode_type == 'cfb':
        return modes.CFB(initialization_vector=iv_or_tweak)
    elif mode_type == 'cfb8':
        return modes.CFB8(initialization_vector=iv_or_tweak)
    elif mode_type == 'ctr':
        return modes.CTR(nonce=iv_or_tweak)
    elif mode_type == 'gcm':
        return modes.GCM(initialization_vector=iv_or_tweak)
    else:
        return None


def decrypt(cipher, mode, key, iv, encrypted_content):
    if cipher == 'aes':
        symkey = AES(key)
    elif cipher == 'tripledes':
        symkey = TripleDES(key)
    else:
        symkey =TripleDES(key)

    cipher = Cipher(symkey, mode_for_type(mode_type=mode, iv_or_tweak=iv), backend=default_backend())
    decryptor = cipher.decryptor()

    return decryptor.update(encrypted_content) + decryptor.finalize()


def encrypt(cipher, mode, key, iv, plain_content):
    key_function = {
        'aes': AES,
        '3des': TripleDES,
        'des': TripleDES
    }[cipher]

    symkey = key_function(key)

    padder = PKCS7(key_function.block_size).padder()
    padded = padder.update(plain_content)
    padded += padder.finalize()

    cipher = Cipher(symkey, mode_for_type(mode_type=mode, iv_or_tweak=iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return key, iv, ciphertext
