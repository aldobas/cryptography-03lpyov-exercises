import base64
import json
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

plaintext = b'This is the secret message to encrypt'

key = get_random_bytes(32)
nonce = get_random_bytes(12)

cipher = ChaCha20.new(key=key,nonce=nonce)
ciphertext = cipher.encrypt(plaintext)

nonceb64 = base64.b64encode(cipher.nonce).decode()
ciphertextb64 = base64.b64encode(ciphertext).decode()
result = json.dumps({'nonce':nonceb64, 'ciphertext':ciphertextb64})
print(result)


#unpack and decipher
b64 = json.loads(result)
ciphertext2 = base64.b64decode(b64['ciphertext'])
nonce2 = base64.b64decode(b64['nonce'])
print(nonce2)
print(nonce)

cipher_dec = ChaCha20.new(key=key,nonce=nonce2)
plaintext_dec = cipher_dec.decrypt(ciphertext2)

# smarter use of JSON objects even more useful when more data are saved
# json_k = [ 'nonce', 'ciphertext']
# json_v = [ base64.b64encode(x).decode() for x in (cipher.nonce, ciphertext) ]
# result2 = json.dumps(dict(zip(json_k, json_v)))
# print(result2)
#
# b64 = json.loads(result2)
# json_k = [ 'nonce', 'ciphertext']
# jv = {k:base64.b64decode(b64[k]) for k in json_k}
#
# cipher_dec = ChaCha20.new(secret=secret,nonce=jv['nonce'])
# plaintext_dec = cipher_dec.decrypt(jv['ciphertext'])
#

print(plaintext_dec)
