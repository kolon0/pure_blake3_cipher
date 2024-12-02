import secrets
from blake3 import blake3
import hmac

class MACMismatchException(Exception):
    pass

def init_blake3_cipher(key):
    def derive_key(context):
        return blake3(key, derive_key_context=context).digest()

    key_ciphertext = derive_key("ciphertext")
    key_mac = derive_key("mac")
    # we seperate keys of encryption and mac
    # blake3 is also kdf

    def encrypt(plaintext):
        # if you don't want assertions to run, use python's -O flag
        assert type(plaintext) == bytes, "plaintext must be bytes type"
        assert len(plaintext) > 0, "plaintext length must be bigger than zero"
        
        nonce = secrets.token_bytes(24)
        # random 192-bit nonce for every plaintext
        
        keystream = blake3(nonce, key=key_ciphertext).digest(length=len(plaintext))
        # blake3 is also xof
        
        ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
        # xor plaintext with keystream
        
        mac = blake3(nonce + ciphertext, key=key_mac).digest()
        # to detect modification of ciphertext, nonce or mac
        
        return (ciphertext, mac, nonce)

    def decrypt(ciphertext, given_mac, nonce):
        assert type(ciphertext) == bytes, "ciphertext must be bytes type"
        assert type(given_mac) == bytes, "mac must be bytes type"
        assert type(nonce) == bytes, "nonce must be bytes type"
        assert len(ciphertext) > 0, "ciphertext length must be bigger than zero"
        assert len(given_mac) == 32, "mac length must be 32"
        assert len(nonce) == 24, "nonce length must be 24"
        
        calculated_mac = blake3(nonce + ciphertext, key=key_mac).digest()

        if not hmac.compare_digest(calculated_mac, given_mac):
            raise MACMismatchException("mac mismatched")
            # possible mitm?
            
        keystream = blake3(nonce, key=key_ciphertext).digest(length=len(ciphertext))
        # we generate the same keystream that is used for encrypt the plaintext
        
        plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
        # xor ciphertext with keystream

        return plaintext

    return (encrypt, decrypt)
