import base64
import sys
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes


plaintext = b'This is the secret message to encrypt'

key = get_random_bytes(ChaCha20.key_size)

cipher = ChaCha20.new(key=key) #nonce is automatically generated

# alternative code if you want to select the nonce explicitly
# nonce = get_random_bytes(12)
# cipher = ChaCha20.new(nonce=nonce, secret=secret)

ciphertext = cipher.encrypt(plaintext)

print("Ciphertext= "+base64.b64encode(ciphertext).decode())
print("Nonce=      "+base64.b64encode(cipher.nonce).decode())

print(sys.getsizeof(plaintext),end=" ")
print(sys.getsizeof(ciphertext))
print(len(cipher.nonce))
