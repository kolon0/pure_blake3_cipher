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

    def encrypt(plaintext, associated_data=b""):
        """Encrypts the plaintext with associated data and returns ciphertext, MAC, and nonce.

        Args:
            plaintext (bytes): The data to be encrypted.
            associated_data (bytes): Optional associated data to be authenticated.

        Returns:
            tuple: (ciphertext, mac, nonce)
        """
        # if you don't want assertions to run, use python's -O flag
        assert type(plaintext) == bytes, "plaintext must be bytes type"
        assert type(associated_data) == bytes, "associated data must be bytes type"
        assert len(plaintext) > 0, "plaintext length must be bigger than zero"
        
        nonce = secrets.token_bytes(24)
        keystream = blake3(nonce, key=key_ciphertext).digest(length=len(plaintext))
        ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
        mac = blake3(nonce + associated_data + ciphertext, key=key_mac).digest()
        
        return (ciphertext, mac, nonce)

    def decrypt(ciphertext, given_mac, nonce, associated_data=b""):
        """Decrypts the ciphertext with associated data and returns the plaintext.

        Args:
            ciphertext (bytes): The encrypted data.
            given_mac (bytes): The MAC of the ciphertext and associated data.
            nonce (bytes): The nonce used during encryption.
            associated_data (bytes): Optional associated data to be authenticated.

        Returns:
            bytes: The decrypted plaintext.

        Raises:
            MACMismatchException: If the MAC verification fails.
        """
        assert type(ciphertext) == bytes, "ciphertext must be bytes type"
        assert type(given_mac) == bytes, "mac must be bytes type"
        assert type(nonce) == bytes, "nonce must be bytes type"
        assert type(associated_data) == bytes, "associated data must be bytes type"
        assert len(ciphertext) > 0, "ciphertext length must be bigger than zero"
        assert len(given_mac) == 32, "mac length must be 32"
        assert len(nonce) == 24, "nonce length must be 24"
        
        calculated_mac = blake3(nonce + associated_data + ciphertext, key=key_mac).digest()

        if not hmac.compare_digest(calculated_mac, given_mac):
            raise MACMismatchException("mac mismatched")
            
        keystream = blake3(nonce, key=key_ciphertext).digest(length=len(ciphertext))
        plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])

        return plaintext

    return (encrypt, decrypt)
