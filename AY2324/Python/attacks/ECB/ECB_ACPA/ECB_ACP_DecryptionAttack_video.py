import os
import string
from math import ceil

from Crypto.Cipher import AES

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

from myconfig import HOST, PORT

if __name__ == '__main__':
    # server = remote(HOST,PORT)
    # message = b"A"*10
    # server.send(message)
    # ciphertext = server.recv(1024)
    # server.close()
    # print(ciphertext.hex())
    # print(len(ciphertext))

    # message = """Here is the msg:{0} - and the sec:{1}""".format(input0, ecb_oracle_secret)
    prefix = b'Here is the msg:'
    postfix = b' - and the sec:'
    print(len(prefix))
    print(len(postfix))

    # for guess in string.printable:
    #     message = postfix + guess.encode()
    #     full_string = prefix + message + postfix + b'?'
    #     print(full_string)
    #     for i in range(ceil(len(full_string)/AES.block_size)):
    #         print(full_string[i*16:(i+1)*16])

    for guess in string.printable:
        message = postfix + guess.encode()
        server = remote (HOST,PORT)
        server.send(message)
        ciphertext = server.recv(1024)
        server.close()
        if ciphertext[16:32] == ciphertext[32:48]:
            print("Found 1st char=" + guess)
            break


    # for guess in string.printable:
    #     message = postfix[1:] + b'H' + guess.encode() + b'A'*(AES.block_size-1)
    #     full_string = prefix + message + postfix + b'??'
    #     print(full_string)
    #     for i in range(ceil(len(full_string)/AES.block_size)):
    #         print(full_string[i*16:(i+1)*16])

    secret = b''
    for i in range(AES.block_size):
        pad = (AES.block_size - i ) * b'A'
        for guess in string.printable:
            message = postfix + secret + guess.encode() + pad
            print(message)

            server = remote(HOST, PORT)
            server.send(message)
            ciphertext = server.recv(1024)
            server.close()

            if ciphertext[16:32] == ciphertext[48:64]:
                print("Found=" + guess)
                secret+= guess.encode()
                postfix = postfix[1:]
                break
    print(secret)
