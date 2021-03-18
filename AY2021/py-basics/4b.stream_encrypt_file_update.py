# This program encrypt the content of the file passed as first argument
# and saves the ciphertext in the file whose name is passed as second argument

from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
import base64
import sys

from mysecrets import salsa_key

nonce = get_random_bytes(8)
streamcipher = Salsa20.new(salsa_key,nonce)

f_output = open(sys.argv[2],"wb")

with  open(sys.argv[1],"rb") as f_input:
    plaintext = f_input.read(1024)
    ciphertext = streamcipher.encrypt(plaintext)
    f_output.write(ciphertext)


print("nonce = "+base64.b64encode(streamcipher.nonce).decode())
