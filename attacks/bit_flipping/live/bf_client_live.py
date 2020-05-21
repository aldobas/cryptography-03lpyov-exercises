from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *





if __name__ == '__main__':

    ADDRESS = "localhost"
    PORT = 12341


    server = remote(ADDRESS, PORT)

    # client code goes here

    # admin=1 in the encrypted cookie

    # expects the username
    # send the encrypted cookie
    # forge a payload to become administrators

    # b'username='+username+b',admin=0' --> longer than one block --> good news
    # username=    | 16 bytes  ,admin=0 padding

    username = 'aldo12'
    server.send(username.encode())


    encrypted_cookie = server.recv(1024)

    # first block username=aldo12,  second block admin=0 9 9 9 9 9 .. 9

    #second block must become admin=1 9 9 9 9 9 .. 9

    # generate a bitflipping mask --> use it on the ciphertext
    # but on the first block

    old_block = pad(b'admin=0',AES.block_size)
    print(old_block)
    new_block = pad(b'admin=1',AES.block_size)
    print(new_block)

    # bytearray -> make it editable
    cookie_array = bytearray(encrypted_cookie)
    starting_byte = 0 #from 0 to 15
    ending_byte = 16

    mask = bytes( a ^ b for (a,b) in zip(old_block,new_block) )
    print(mask)

    for i in range (starting_byte,ending_byte):
        cookie_array[i] ^= mask[i]

    server.send(cookie_array)

    msg = server.recv(1024)

    print(msg.decode('utf-8'))


    server.close()
