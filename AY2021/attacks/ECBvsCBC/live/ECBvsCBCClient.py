import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

from mysecrets import HOST, PORT


# first connect to the server and get a response
server = remote(HOST, PORT)

input = b'This is a message'

server.send(input)
ciphertext = server.recv(1024)
print(ciphertext.hex())

server.close()

# print some info

# message = "This is what I received: " + input + " -- END OF MESSAGE"
s1 = "This is what I received: "
s2 = " -- END OF MESSAGE"
print(len(s1))

input = "A" * 512

server = remote(HOST, PORT)

server.send(input)
ciphertext = server.recv(1024)
c_hex = ciphertext.hex()

print(c_hex[64:96])
print(c_hex[96:128])

if ciphertext[32:48] == ciphertext[48:64]:
    print("The server used ECB")
else:
    print("The server used CBC")



server.close()


# "This is what I received: "
# AES block size = 16
#
# This is what I r
# eceived: AAAAAAA
# aaaaaaaaaaaaaaaa
# aaaaaaaaaaaaaaaa


"a"*16
"a"*16
