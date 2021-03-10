import base64
import sys
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

plaintext = b'This is the secret message to encrypt'

key = get_random_bytes(32)

# cipher = ChaCha20.new(key=key) #nonce is automatically generated
nonce = get_random_bytes(8)
ciphertext = cipher.encrypt(plaintext)

print("Ciphertext="+base64.b64encode(ciphertext).decode('utf-8'))
print("Nonce="+base64.b64encode(cipher.nonce).decode('utf-8'))

print(sys.getsizeof(plaintext),end=" ")
print(sys.getsizeof(plaintext))
