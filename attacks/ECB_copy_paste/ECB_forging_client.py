from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *

from mysecrets import ecb_oracle_key,HOST,PORT


# if __name__ == '__main__':
#
#     # x= "foo=bar&baz=qux&zap=zazzle"
#     # d = parse(x)
#     # print(d)
#     # s= encode_profile(d)
#     # print(s)
#     # d= profile_for("a@b.com&role=admin")
#     # print(d)
#
#
#     s = "email=aaaaaaa@b.com&UID=10&role="
#     # print(len(s))
#     # print(pad("admin".encode(),AES.block_size))
#
#     email_test = "aaaaaaa@b.com" # last_block is user --> admin
#
#     c1 = encrypt_profile(encode_profile(profile_for(email_test)))
#     print(c1)
#     print(len(c1))
#     print(decrypt_msg(c1))
#
#     empty_admin = b'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
#     email2 = "aaaaaaaaaa"+pad("admin".encode(),AES.block_size).decode()
#     print(email2)
#     c2 = encrypt_profile(encode_profile(profile_for(email2)))
#     print(c2)
#
#
#     ciphertext_attack = bytearray()
#     ciphertext_attack += c1[0:2*AES.block_size]
#     ciphertext_attack += c2[AES.block_size:2*AES.block_size]



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

