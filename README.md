# pure_blake3_cipher
It is a simple stream cipher with mac that only uses blake3. **It is NOT for production.** It is for fun!

# How to use it?
```python
import secrets
from pure_blake3_cipher import init_blake3_cipher

key = secrets.token_bytes(32) # Your super secret 256-bit key.
encrypt, decrypt = init_blake3_cipher(key)

plaintext = "encrypt what you want".encode("utf-8") # utf-16 and utf-32 also works
aad = "optional additional associated data".encode("utf-8")

ciphertext, mac, nonce = encrypt(plaintext, aad)
plaintext = decrypt(ciphertext, mac, nonce, aad).decode("utf-8")

print(f"Ciphertext: {ciphertext.hex()}")
print(f"Plaintext: {plaintext}")
```
**Note:** We handle mac check internally. So you should check the code. It is really a simple code with comments.
