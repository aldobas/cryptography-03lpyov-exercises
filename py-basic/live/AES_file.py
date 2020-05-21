from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
import base64
import json

from ../mysecrets import aes_key

iv = get_random_bytes(AES.block_size)
cipher = AES.new(aes_key, AES.MODE_CBC, iv)

f_input = open(sys.argv[1],"rb")

#pycryptodome does not support update functions for block ciphers
ciphertext = cipher.encrypt(pad(f_input.read(),AES.block_size))

#an IV and a ciphertext as binary objects: don't go easily in the web
#JSON objects are good representations of string, organized
ivb64 = base64.b64encode(cipher.iv).decode('utf-8') # is a string, good for JSON objects
ciphertextb64 = base64.b64encode(ciphertext).decode('utf-8') # is a string, good for JSON objects
json_object = json.dumps({'IV':ivb64, 'ciphertext':ciphertextb64})

print(json_object)

# here I am the recipient: I received a json_file

b64 = json.loads(json_object) # split it so that I can manipulate them: hash map / dictionary
#prepare the decryption object
iv_at_recipient = base64.b64decode(b64['IV'])
cipher2 = AES.new(aes_key, AES.MODE_CBC, iv_at_recipient)
ciphetext_at_recipient = base64.b64decode(b64['ciphertext'])
plaintext_dec = cipher2.decrypt(ciphetext_at_recipient)
plaintext_dec_unpadded = unpad(plaintext_dec,AES.block_size)
print(plaintext_dec_unpadded)
