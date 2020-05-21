from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *

from mysecrets import HOST,PORT

if __name__ == '__main__':

    # first connection: exclude user by isolating it in a different block

    server = remote(HOST, PORT)
    email1 = "aaaaaaa@b.com"
    server.send(email1)
    c1 = server.recv(1024)
    server.close()

    # second: ask to create the last block we need
    # admin padded \x0b 11 times

    server = remote(HOST, PORT)
    email2 = "aaaaaaaaaa" + pad("admin".encode(),AES.block_size).decode()
    server.send(email2)
    c2 = server.recv(1024)
    server.close()

    ciphertext_attack = bytearray()
    ciphertext_attack += c1[0:2*AES.block_size]
    ciphertext_attack += c2[AES.block_size:2*AES.block_size]

    test = remote(HOST, PORT+100)
    test.send(ciphertext_attack)
    msg = test.recv(1024)
    print(msg.decode())
    test.close()
