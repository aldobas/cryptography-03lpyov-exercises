
from pwn import *
import string
from Crypto.Cipher import AES
from math import ceil

from mysecrets import HOST,PORT

SECRET_LEN = 0

secret = ""

# message = """Here is the message:{0} and here is the secret:{1}""".format( input0, ecb_oracle_long_secret)

prefix = "Here is the message:"
mid = " and here is the secret:"

#determining the length of the secret, estimate padding
prev_len = 0
for i in range(1,AES.block_size+1):
    server = remote(HOST, PORT)
    msg = "A"*i
    print("Sending: "+msg)
    server.send(msg.encode())
    ciphertext = server.recv(1024)
    if len(ciphertext)>prev_len:
        if prev_len==0:
            prev_len = len(ciphertext)
            print("updated length = "+str(len(ciphertext)))
        else:
            # 2 full blocks - len of input = i - len of fixed strings
            SECRET_LEN = prev_len - (i) - len(prefix) - len(mid)
            print("SECRET LENGTH " + str(SECRET_LEN))
            break
    server.close()




SIZE = max(len(mid),SECRET_LEN)

BLOCKS = math.ceil(SIZE/AES.block_size)*AES.block_size

# align the block to check
pad0 = ceil(len(prefix)/AES.block_size)*AES.block_size - len(prefix)
print(pad0)
# the block to check will start at byte 32

#2 block useless
# 2 blocks: pad1 + mid + 1 char
pad1 = ceil((len(mid)+SECRET_LEN)/AES.block_size)*AES.block_size - len(mid) - 1
print(ceil((len(mid)+SECRET_LEN)/AES.block_size)*AES.block_size)
print(pad1)


#0 Here is the mess| age:AAAAAAAAAAAA |  is the secret:l | AAAAAAAand here | is the secret:?
#1 Here is the mess| age:AAAAAAAAAAAA |  s the secret:ll | AAAAAAand here | is the secret:??
#  0                 16                 32                 48                 64                80
#0 Here is the mess| age:AAAAAAAAAAAA |  is the secret:l | AAAAAAAAAAAAAAAA | AAAAAAAAAAAAAAAA | AAAAAAAand here | is the secret:? | ???????????????? | ?????????
#1 Here is the mess| age:AAAAAAAAAAAA |  s the secret:ll | AAAAAAAAAAAAAAAA | AAAAAAAAAAAAAAAA | AAAAAAand here i| s the secret:?? | ???????????????? | ????????

# room: 31 +

#determining the secret
for i in range(0,SECRET_LEN):
    for letter in string.printable:

        server = remote(HOST, PORT)

        msg = "A"*pad0 # 12  bytes
        msg+= mid[len(mid)-AES.block_size+1:] # 15 bytes
        print(mid[len(mid)-AES.block_size+1:])
        msg+=letter # 1 byte
        msg+="A"*pad1 # decreasing from 7+16+16

        print(str(i)+":"+str(SECRET_LEN)+":Sending: "+msg)
        server.send(msg.encode())
        ciphertext = server.recv(1024)

        server.close()


        #check
        if ciphertext[32:32+AES.block_size] == ciphertext[96:96+AES.block_size]:
            print("Found new character = "+letter)
            secret+=letter
            mid+=letter
            pad1-=1
            break



print("Secret discovered = "+secret)
