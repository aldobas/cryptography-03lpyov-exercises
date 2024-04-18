from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from attacks.ECB.myconfig import HOST, PORT, DELTA_PORT

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

from attacks.ECB.ECBCopyPaste.ECB_CopyPaste_server_genCookie_service import profile_for,encode_profile

if __name__ == '__main__':
    server_gencookies = remote(HOST,PORT)
    email = b'aaaaaaa@b.com'

    server_gencookies.send(email)
    encrpyted_cookie = server_gencookies.recv(1024)
    print(encrpyted_cookie)

    cookie_info = encode_profile(profile_for(email.decode()))
    print(cookie_info)
    print(cookie_info[0:16])
    print(cookie_info[16:32])

    padded_admin = b'A'*10 + pad( b'admin', AES.block_size)
    cookie_info = encode_profile(profile_for(padded_admin.decode()))
    print(cookie_info[0:16])
    print(cookie_info[16:32].encode())
    server_gencookies.close()

    server_gencookies = remote(HOST, PORT)
    server_gencookies.send(padded_admin)
    encrpyted_cookie_2 = server_gencookies.recv(1024)
    server_gencookies.close()

    print(encrpyted_cookie_2)

    auth_cookie = encrpyted_cookie[0:32] + encrpyted_cookie_2[16:32]
    server_test = remote(HOST, PORT+DELTA_PORT)
    server_test.send(auth_cookie)
    answer = server_test.recv(1024)

    print(answer.decode())


