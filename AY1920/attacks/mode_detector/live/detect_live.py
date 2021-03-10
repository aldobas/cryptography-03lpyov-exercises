from pwn import *
from math import ceil

from mysecrets import HOST,PORT

BLOCK_SIZE_HEX = 32
BLOCK_SIZE = 16


# message = "This is what I received: " + input0 + " -- END OF MESSAGE"
# "This is what I received: "

server = remote(HOST, PORT)

start_str = "This is what I received: " # --> 32 bytes after the padding
pad_len = ceil(len(start_str)/BLOCK_SIZE)*BLOCK_SIZE-len(start_str) # 32 - 25
print(pad_len)

# msg  padding + 2 entire blocks
msg = "A"*(16*2+pad_len) # plaintext message to send to the server
print("Sending: "+msg)
server.send(msg)
ciphertext = server.recv(1024)
ciphertext_hex = ciphertext.hex()

server.close()

for i in range(0,int(len(ciphertext_hex)/BLOCK_SIZE_HEX)):
    print(ciphertext_hex[i*BLOCK_SIZE_HEX:(i+1)*BLOCK_SIZE_HEX])

# 0        16              32       48
# prefix | prefix+padding | block | block | I don't care

print("Selected mode is = ",end='')
if ciphertext[2*BLOCK_SIZE:3*BLOCK_SIZE] == ciphertext[3*BLOCK_SIZE:4*BLOCK_SIZE]:
    print("ECB")
else:
    print("CBC")

