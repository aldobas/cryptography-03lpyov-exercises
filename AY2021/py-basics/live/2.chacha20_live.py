
#encrypt with ChaCha20
#using a random key

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import base64

key = get_random_bytes(32)
nonce = get_random_bytes(12) #96 bits


cipher = ChaCha20.new(key=key,nonce=nonce) #didn't pass the nonce

plaintext = b'This is the message to encrypt'
# p = 'This is the message to encrypt'

ciphertext = cipher.encrypt(plaintext)
# ciphertext = cipher.encrypt(p)

print(ciphertext)

print(cipher.nonce)

nonceb64 = base64.b64encode(cipher.nonce)
ciphertextb64= base64.b64encode(ciphertext)

print(nonceb64) # bytes object
print("The nonce is: " + nonceb64.decode())
print("The ciphertext is: " + ciphertextb64.decode())

#python casting problem
# print(ciphertext.decode())

# here we are at the recipient
#############################################33
# the key has been exchanged in a secure

# ciphertext64 and nonceb64 have been received from the Internet
cipher_dec = ChaCha20.new(key=key,nonce=base64.b64decode(nonceb64))
ciphertext_extracted = base64.b64decode(ciphertextb64)
decrypted = cipher_dec.decrypt(ciphertext_extracted)

print(decrypted)
