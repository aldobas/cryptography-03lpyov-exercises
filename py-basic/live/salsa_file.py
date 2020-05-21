#encrypt the content of the file argv[1]
#store ciphertext in the file argv[2]
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import base64
import sys

key = get_random_bytes(32)

cipher = ChaCha20.new(key=key)

f_output = open(sys.argv[2],"wb")

with  open(sys.argv[1],"rb") as f_input:
    plaintex = f_input.read(1024)
    ciphertext = cipher.encrypt(plaintex)
    f_output.write(ciphertext)

print("Nonce = " + base64.b64encode(cipher.nonce).decode('utf-8'))
