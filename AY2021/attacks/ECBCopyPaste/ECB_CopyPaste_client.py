from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *

from mysecrets import ecb_oracle_key,HOST,PORT


if __name__ == '__main__':


    server = remote(HOST, PORT)
    email1 = "aaaaaaa@b.com"
    print("User: " + email1)
    server.send(email1.encode())
    c1 = server.recv(1024)
    server.close()

    server = remote(HOST, PORT)
    email2 = "aaaaaaaaaa"+pad("admin".encode(),AES.block_size).decode()
    print("User: " + email2)
    server.send(email2.encode())
    c2 = server.recv(1024)
    server.close()

    test = remote(HOST, PORT+100)
    ciphertext_attack = bytearray()
    ciphertext_attack += c1[0:2*AES.block_size]
    ciphertext_attack += c2[AES.block_size:2*AES.block_size]
    test.send(ciphertext_attack)
    msg = test.recv(1024)
    print(msg.decode())
    test.close()

