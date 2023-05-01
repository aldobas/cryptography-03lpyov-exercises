import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from math import ceil
from Crypto.Cipher import AES

from attacks.ECB.myconfig import HOST,PORT



BLOCK_SIZE = AES.block_size
BLOCK_SIZE_HEX = 2*BLOCK_SIZE


server = remote(HOST, PORT)

# stole from the server code...
# message = "This is what I received: " + msg + " -- END OF MESSAGE"
start_str = "This is what I received: "
# print(len(start_str))
pad_len = ceil(len(start_str)/BLOCK_SIZE)*BLOCK_SIZE-len(start_str)

msg = b"A"*(16*2+pad_len) #2 * AES.block_size + oad_len
print("Sending: "+str(msg))
server.send(msg)


ciphertext = server.recv(1024)
ciphertext_hex = ciphertext.hex()
print(ciphertext_hex)

server.close()

for i in range(0,int(len(ciphertext_hex)//BLOCK_SIZE_HEX)):
    print(ciphertext_hex[i*BLOCK_SIZE_HEX:(i+1)*BLOCK_SIZE_HEX])


print("Selected mode is", end=' ')
if ciphertext[2*BLOCK_SIZE:3*BLOCK_SIZE] == ciphertext[3*BLOCK_SIZE:4*BLOCK_SIZE] :
    print("ECB")
else:
    print("CBC")
