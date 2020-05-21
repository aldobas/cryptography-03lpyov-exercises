from pwn import *
from math import ceil

from mysecrets import ecb_oracle_key,HOST,PORT


BLOCK_SIZE_HEX = 32
BLOCK_SIZE = 16



# server = remote(ADDRESS, PORT)
# msg = "just a msg"
# print("Sending: "+msg)
# server.send(msg)
# ciphertext = server.recv(1024).hex()
# print(ciphertext)
#
# server.close()
#
#
# print
# for i in range(0,int(len(ciphertext)/BLOCK_SIZE_HEX)):
#     print(ciphertext[i*BLOCK_SIZE_HEX:(i+1)*BLOCK_SIZE_HEX])


server = remote(HOST, PORT)



# message = "This is what I received: " + msg + " -- END OF MESSAGE"

start_str = "This is what I received: " #26 chars
print(len(start_str))
pad_len = ceil(len(start_str)/BLOCK_SIZE)*BLOCK_SIZE-len(start_str) # 32 - 26

msg = "A"*(16*2+pad_len) #2 * AES.block_size + oad_len
print("Sending: "+msg)
server.send(msg)


ciphertext = server.recv(1024)
ciphertext_hex = ciphertext.hex()
print(ciphertext_hex)

server.close()

for i in range(0,int(len(ciphertext_hex)/BLOCK_SIZE_HEX)):
    print(ciphertext_hex[i*BLOCK_SIZE_HEX:(i+1)*BLOCK_SIZE_HEX])


print("Selected mode is", end=' ')
if ciphertext[2*BLOCK_SIZE:3*BLOCK_SIZE] == ciphertext[3*BLOCK_SIZE:4*BLOCK_SIZE] :
    print("ECB")
else:
    print("CBC")
