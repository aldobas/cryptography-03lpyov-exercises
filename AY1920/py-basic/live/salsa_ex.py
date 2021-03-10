from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
import base64

plaintext = b'This is the secret message to encrypt'
plaintext2 = b'And this is the second part of the secret message to encrypt'

key = get_random_bytes(32)
nonce = get_random_bytes(8)

cipher = Salsa20.new(key=key) # object ready to encrypt
ciphertext = cipher.encrypt(plaintext)
ciphertext += cipher.encrypt(plaintext2)

#base64
print(ciphertext)

b64 = base64.b64encode(ciphertext)
print("Ciphertext = "+b64.decode('utf-8'))
print("Nonce = " + base64.b64encode(cipher.nonce).decode('utf-8'))

#key shared in some secure way
cipher2 = Salsa20.new(key=key,nonce=cipher.nonce)
plaintext_dec = cipher2.decrypt(ciphertext)

print(plaintext_dec)
