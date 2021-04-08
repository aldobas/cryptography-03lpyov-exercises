import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ADDRESS = "localhost"
PORT = 12346


#connect
server = remote(ADDRESS, PORT)

#generate a username
username = "aldo" #str --> .encode()

#send the username
server.send(username.encode())

#receive the ciphertext
ciphered_cookie = server.recv(1024)
print(ciphered_cookie)
print(len(ciphered_cookie))

#build a valid cookie to edit
cookie = pad(b'username='+username.encode()+b',admin=0',AES.block_size)


print(cookie[:16])
print(cookie[16:])
# username=aldo11, || admin=0
# garbage          || admin=1 // admin=1

# username=aldo,ad || min=0
# after the bit flipping with CBC
# garbage          || min=1 // server is checking for substring 'admin=1'


#build the mask
old_block = cookie[16:]
print(old_block)
new_block = pad(b'admin=1',AES.block_size)
print(new_block)



#create an editable ciphertext
cookie_array = bytearray(ciphered_cookie)
mask = bytearray(AES.block_size)

for i in range(AES.block_size):
    mask[i] = old_block[i] ^ new_block[i]
print(mask)

for i in range(AES.block_size):
    cookie_array[i] ^= mask[i]
print(cookie_array)
print("          " + str(ciphered_cookie))



#send the ciphertext
server.send(cookie_array)

#receive the ciphertext
msg = server.recv(1024)
print(msg.decode())
#close the connection
server.close()
