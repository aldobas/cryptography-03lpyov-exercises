# An encryption oracle, listening on IP:port, receives as input a string and
# returns another string that encodes in hexadecimal the result of the
# encryption with AES in ECB mode of the following plaintext
# message = """Here is the msg:{0} - and the key:{1}""".format( input, secret)
# where input is the string received as input and secret is
# a secret string, composed of 16 printable characters
# Complete the program so that the secret is discovered without bruforcing
# the whole search space

#!/usr/bin/python2 -u
from pwn import *
import string
from math import ceil

from mysecrets import HOST,PORT

# ADDRESS = "localhost"
# PORT = 12341
BLOCK_SIZE_HEX = 32
BLOCK_SIZE = 16
MAX_INDEX = 5

server = remote(HOST, PORT)



start_str = "This is what I received: "
print(len(start_str))
pad_len = ceil(len(start_str)/BLOCK_SIZE)*BLOCK_SIZE-len(start_str)

msg = "A"*(BLOCK_SIZE*(MAX_INDEX+1)+pad_len)
print("Sending: "+msg)

#0 "This is what I 0"
#1 "received: AAAAA1"
#2 "AAAAAAAAAAAAAAA2"
#3 "AAAAAAAAAAAAAAA3"
#4 "AAAAAAAAAAAAAAA4"
#5 "AAAAAAAAAAAAAAA0"
#6 "AAAAAAAAAAAAAAA1"
#7 "AAAAAAAAAAAAAAA2"
#8 "AAAAAAAAAAAAAAA3"


server.send(msg)
ciphertext = server.recv(1024)
ciphertext_hex = ciphertext.hex()
# print(ciphertext_hex)

server.close()


for i in range(0,int(len(ciphertext_hex)/BLOCK_SIZE_HEX)):
    print(ciphertext_hex[i*BLOCK_SIZE_HEX:(i+1)*BLOCK_SIZE_HEX])


print("Selected mode is", end=' ')
if ciphertext[2*BLOCK_SIZE:3*BLOCK_SIZE] == ciphertext[(MAX_INDEX+2)*BLOCK_SIZE:(MAX_INDEX+3)*BLOCK_SIZE] :
    print("ECB")
else:
    print("CBC")
