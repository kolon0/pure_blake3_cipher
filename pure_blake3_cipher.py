import secrets
from blake3 import blake3
import hmac

def init_blake3_cipher(key):
    def derive_key(context):
        return blake3(key, derive_key_context=context).digest()

    key_ciphertext = derive_key("ciphertext")
    key_mac = derive_key("mac")
    # We seperate keys of encryption and mac with key derivation feature of blake3.

    def encrypt(plaintext): # If plaintext is a string, you have to encode it before using that function. For example: plaintext.encode("utf-8")
        nonce = secrets.token_bytes(24)
        # We always generate a random 192-bit nonce for every given plaintext. Hence, it is practically impossible to generate same nonce twice.

        keystream = blake3(nonce, key=key_ciphertext).digest(length=len(plaintext))
        # The keystream is same length as plaintext. Thanks to the blake3's XOF feature.
        
        ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
        # It is just doing XOR with plaintext and keystream.
    
        mac = blake3(nonce + ciphertext, key=key_mac).digest()
        # It is for validating given nonce and ciphertext is not modified by Eve.

        return (ciphertext, mac, nonce)

    def decrypt(ciphertext, given_mac, nonce):
        calculated_mac = blake3(nonce + ciphertext, key=key_mac).digest()

        if not hmac.compare_digest(calculated_mac, given_mac):
            raise Exception("Sorry, the given mac is not matching the calculated mac.")

        keystream = blake3(nonce, key=key_ciphertext).digest(length=len(ciphertext))
        # We generate same keystream that is used to encrypt the plaintext.
        
        plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
        # It is just doing XOR with ciphertext and keystream.

        return plaintext

    return (encrypt, decrypt)
