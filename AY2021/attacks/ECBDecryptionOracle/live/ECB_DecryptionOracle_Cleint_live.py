import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

from mysecrets import HOST, PORT

from Crypto.Cipher import AES



# message = """Here is the msg:{0} - and the sec:{1}""".format( input0, ecb_oracle_secret)

print(len("Here is the msg:")) # my input will start at the beginning of the second block
print(len(" - and the sec:")) # miss one byte to fill a whole block

fixed_intermediate = " - and the sec:"

# create a server, connect and close
server = remote(HOST,PORT)
input = "A"*AES.block_size

server.send(input)
ciphertext = server.recv(1024)
print(ciphertext.hex())

server.close()

server = remote(HOST,PORT)
input = " - and the sec:" + "H"

# "Here is the msg:"
# "- and the sec:A"
# "- and the sec:?"

server.send(input.encode())

ciphertext = server.recv(1024)
print(ciphertext.hex())

c_hex = ciphertext.hex()
print(c_hex[32:64])
print(c_hex[64:96])


server.close()


secret = ""
pad = "A" * 16
for i in range(AES.block_size):
    # pad = "A" * (16-i)
    for letter in string.printable:
        input = fixed_intermediate + secret + letter + pad
        print(input)
        server = remote(HOST,PORT)
        server.send(input.encode())

        ciphertext = server.recv(1024)
        # print(ciphertext.hex())

        server.close()

        if ciphertext[16:32] == ciphertext[48:64]:
            print("Found letter="+letter)
            secret = secret + letter
            fixed_intermediate = fixed_intermediate[1:]
            pad = pad[1:]
            print(secret)
            break

print(secret)

#print some iputs stats and lenghts



# iterate over letters
# string = s2
# for letter in string.printable:
#    input = string + letter
#

# check if hypothesis is correct

# server = remote (HOST,PORT)
# server.send(string.encode()+b'a')
# ciphertext = server.recv(1024)
# print(ciphertext.hex())
#server.close()
#
#
# server = remote (HOST,PORT)
# server.send(string.encode()+b'H')
# ciphertext = server.recv(1024)
# print(ciphertext.hex())
# server.close()
#
# c_hex = ciphertext.hex()
# for i in range(3):
#     print(c_hex[i*32:(i+1)*32])



# print("----------------------")
# secret = ""
# for i in range(AES.block_size):
#     pad = "A" * (16 - i)
#     for letter in string.printable:


