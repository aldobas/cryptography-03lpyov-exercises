# encryption with AES + computation of a MAC
# only used for authc+int + encrypted
# AEAD: encrypt the confidential part
# AEAD: computes the MAC on auth-only + confidential part

# create a GCM mode AES 256 cipher
import base64
import json

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
cipher = AES.new(key, AES.MODE_GCM) #uses a nonce

# data
auth_only_data = b'this is the part to authenticate / header'
confidential_data = b'this part should be kept secret'



#pass the header --> update function

cipher.update(auth_only_data)

# get ciphertext and tag
ciphertext, tag = cipher.encrypt_and_digest(confidential_data)


#pack data
keys = ['ciphertext', 'tag', 'header', 'nonce'] # we omit the algorithm name
# data = [base64.b64encode(ciphertext).decode(), base64.b64encode(tag).decode(), auth_only_data.decode(), base64.b64encode(cipher.nonce).decode()]
data = [base64.b64encode(x).decode() for x in (ciphertext, tag, auth_only_data, cipher.nonce)]

print(type(base64.b64encode(tag).decode().encode()))
print(type(base64.b64encode(tag)))


packed_data = json.dumps(dict(zip(keys,data)))
print(packed_data)


###################################
# key received securely

# extract packed data
unpacked_data = json.loads(packed_data)


# create cipher, pass nonce

cipher_verification = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(unpacked_data["nonce"]))

# pass the header
cipher_verification.update(base64.b64decode(unpacked_data["header"].encode()))

# check tag and obtain plaintext
try:
    plaintext = cipher_verification.decrypt_and_verify(base64.b64decode(unpacked_data["ciphertext"]), base64.b64decode(unpacked_data["tag"]))
except ValueError:
    print("ERROR: the MAC is incorrect")

print("MAC is OK and the plaintext is: ", end='')
print(plaintext)
