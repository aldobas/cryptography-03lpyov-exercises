# This program encrypt the content of the file passed as first argument
# and saves the ciphertext in the file whose name is passed as second argument

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import sys


aes_key = get_random_bytes(AES.key_size[0])
iv = get_random_bytes(AES.block_size)

cipher = AES.new(aes_key, AES.MODE_CBC, iv)

f_input = open(sys.argv[1],"rb")

ciphertext = cipher.encrypt(pad(f_input.read(),AES.block_size))

f_output = open(sys.argv[2],"wb")
f_output.write(ciphertext)

print(iv)
