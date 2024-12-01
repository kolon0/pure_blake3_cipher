# pure_blake3_cipher
It is a simple stream cipher with mac that only uses blake3. **It is NOT for production.** It is for fun!

# How to use it?
```python
from pure_blake3_cipher import init_blake3_cipher
import secrets

key = secrets.token_bytes(32) # Your super secret 256-bit key.
encrypt, decrypt = init_blake3_cipher(key)

ciphertext, mac, nonce = encrypt(b"encrypt what you want")
plaintext = decrypt(ciphertext, mac, nonce).decode("utf-8")
print(plaintext)
```
**Note:** We handle mac check internally. So you should check the code. It is really a simple code with comments.
