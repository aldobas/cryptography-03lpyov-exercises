from myconfig import HOST, PORT
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from pwn import *

if __name__ == '__main__':

    # server = remote(HOST,PORT)
    # username = b'aldo'
    # server.send(username)
    # enc_cookie = server.recv(1024)
    #
    # server.send(enc_cookie)
    # ans = server.recv(1024)
    # print(ans)
    # server.close()
    #
    #
    # server = remote(HOST,PORT)
    # username = b'aldo'
    # server.send(username)
    # enc_cookie = server.recv(1024)
    # edt = bytearray(enc_cookie)
    # edt[-1] = 0
    #
    #
    # server.send(edt)
    # ans = server.recv(1024)
    # print(ans)
    # server.close()

    username = b'aldooo11'
    cookie = pad(b'username=' + username + b',admin=0', AES.block_size)
    print(cookie)
    print(cookie[:16], end=' || ')
    print(cookie[16:])


    index = cookie.index(b'0') - AES.block_size
    print(index)
    mask = ord(b'1') ^ ord(b'0')


    server = remote(HOST,PORT)
    server.send(username)
    enc_cookie = server.recv(1024)
    edt = bytearray(enc_cookie)
    edt[index] = edt[index] ^ mask
    server.send(edt)
    ans = server.recv(1024)
    print(ans)
