

# message = """Here is the msg:{0} - and the key:{1}""".format( input0, ecb_oracle_secret)


#0:15  Here is the msg:
#16:31 {0}
#32:47
#48:63 - and the key:s0
#64:79 s1 .. s15 pad

#0:15  Here is the msg:
#16:31 - and the key:? --> iterate on the last char
#32:47 padding --> 16 bytes
#48:63 - and the key:s0
#64:79 s1 .. s15 pad


#0:15  Here is the msg:
#16:31  and the key:S? --> iterate on the last char, S already discovered
#32:47 padding --> 15 bytes  --> -
#48:63  and the key:Ss1
#64:79 s1 .. s15 pad


from Crypto.Cipher import AES
from pwn import *
import string

ADDRESS = "localhost"
PORT = 12345
SECRET_LEN = 16

secret = ""

fix =  " - and the sec:"

print(fix)
print(len(fix))

for i in range(0,SECRET_LEN):
    # msg = fix + secret + current character + pad
    pad = "A"*(AES.block_size - i)

    for letter in string.printable:

        server = remote(ADDRESS, PORT)

        msg = fix + secret + letter + pad
        print("Sending: "+msg)
        server.send(msg)
        ciphertext = server.recv(1024)

        server.close()

        if ciphertext[16:32] == ciphertext[48:64]:
            secret += letter
            fix = fix[1:]
            print("Found new character = "+letter)
            break

print("I discovered the secret = "+secret)
