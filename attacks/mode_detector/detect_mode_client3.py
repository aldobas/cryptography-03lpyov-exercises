# An encryption oracle, listening on IP:port, receives as input a string and
# returns another string that encodes in hexadecimal the result of the
# encryption with AES in ECB mode of the following plaintext
# message = """Here is the msg:{0} - and the key:{1}""".format( input, secret)
# where input is the string received as input and secret is
# a secret string, composed of 16 printable characters
# Complete the program so that the secret is discovered without bruforcing
# the whole search space

#!/usr/bin/python2 -u
from Crypto.Cipher import AES
from pwn import *
import string
from math import ceil

from mysecrets import HOST,PORT

# ADDRESS = "localhost"
# PORT = 12341
BLOCK_SIZE_HEX = 32
BLOCK_SIZE = 16
MAX_BLOCKS = 8

server = remote(HOST, PORT)



start_str = "This is what I received: "
print(len(start_str))
pad_len = ceil(len(start_str)/BLOCK_SIZE)*BLOCK_SIZE-len(start_str)

msg = "A"*(BLOCK_SIZE * (MAX_BLOCKS + 1) + pad_len)
print("Sending: "+msg)


server.send(msg)
ciphertext = server.recv(1024)
ciphertext_hex = ciphertext.hex()
# print(ciphertext_hex)

server.close()


for i in range(0,int(len(ciphertext_hex)/BLOCK_SIZE_HEX)):
    print(ciphertext_hex[i*BLOCK_SIZE_HEX:(i+1)*BLOCK_SIZE_HEX])

print("Selected mode is", end=' ')
block_set = set()
for i in range(2,int(len(ciphertext)/BLOCK_SIZE)):
    current_block = ciphertext[AES.block_size*i:AES.block_size*(i+1)]
    if current_block not in block_set:
        block_set.add(current_block)
    else:
        print("ECB")
        sys.exit(0)

print("CBC")
