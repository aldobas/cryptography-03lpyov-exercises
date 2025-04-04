# An encryption oracle, listening on IP:port, receives as input a string and
# returns another string that encodes in hexadecimal the result of the
# encryption with AES in ECB mode of the following plaintext
# message = """Here is the msg:{0} - and the sec:{1}""".format( input, secret)
# where input is the string received as input and secret is
# a secret string, composed of 16 printable characters
# Complete the program so that the secret is discovered without brute forcing
# the whole search space

from Crypto.Cipher import AES
from pwn import *
import string

from attacks.ECB.myconfig import HOST,PORT

SECRET_LEN = 16

secret = ""


#0:15  Here is the msg:
#16:31 {0}
#32:47
#48:63 - and the key:s0
#64:79 s1 .. s15 pad

#HEX STRING
#0:31    Here is the msg:
#32:63   {0}
#64:95   {0} ...continued
#96:127  - and the key:s0
#128:139 s1 .. s15 pad

#HEX STRING
#0:31    Here is the msg:
#32:63   - and the key:X
#64:95   pad --> starts from one block, decreases at each letter discovered
#96:127  - and the key:s0
#128:139 s1 .. s15 pad

# message = """Here is the msg:{0} - and the key:{1}""".format( input0, ecb_oracle_secret)

fix =" - and the sec:"

for i in range(0,SECRET_LEN):
    pad = "A"*(AES.block_size-i)
    for letter in string.printable:

        server = remote(HOST, PORT)

        msg = fix+secret+letter+pad
        print("Sending: "+msg)
        server.send(msg)
        ciphertext = server.recv(1024)

        server.close()

        if ciphertext[16:32] == ciphertext[48:64]:
            print("Found new character = "+letter)
            secret+=letter
            fix = fix[1:]
            break

print("Secret discovered = "+secret)
