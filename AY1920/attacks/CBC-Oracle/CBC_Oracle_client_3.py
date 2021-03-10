from Crypto.Cipher import AES
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import string

from mysecrets import HOST,PORT, cbc_oracle_iv as iv
from mysecrets import cbc_oracle_ciphertext as ciphertext

# b'r\x8b\x14\xd6\xae{J\xa0\xe3\x9e\n\x96>\xf9=c\x0f\x16\x9at\x80\ny\xcfD\x08\xe7\xbe\xc1\x8d\x06U\x17J\xb4.\xe1\x9b48R\x8d\xd7\x04\xad\x0b\x7f\xbcS\xac\xd9\xb9\xbb\xfaI\x87\xa3E\x8aT8//\xf4\xb0\xa9u\x8c\x0eQ\x1c\x83v\xed\x04`\n\xf7\xcc\x03'

# ciphertext = b'r\x8b\x14\xd6\xae{J\xa0\xe3\x9e\n\x96>\xf9=c\x0f\x16\x9at\x80\ny\xcfD\x08\xe7\xbe\xc1\x8d\x06U\x17J\xb4.\xe1\x9b48R\x8d\xd7\x04\xad\x0b\x7f\xbcS\xac\xd9\xb9\xbb\xfaI\x87\xa3E\x8aT8//\xf4\xb0\xa9u\x8c\x0eQ\x1c\x83v\xed\x04`\n\xf7\xcc\x03'


def num_blocks(ciphertext, block_size):
    return math.ceil(len(ciphertext)/block_size)

#first block is 0
def get_nth_block(ciphertext, n, block_size):
    return ciphertext[(n)*block_size:(n+1)*block_size]

def get_n_blocks_from_m(ciphertext, n, m, block_size):
    return ciphertext[(m)*block_size:(m+n)*block_size]


def check_oracle_good_padding():
    server = remote(HOST, PORT)
    server.send(iv)
    server.send(ciphertext)
    response = server.recv(1024)
    server.close()
    print("Oracle said: "+response.decode())


def check_oracle_bad_padding():
    server = remote(HOST, PORT)
    server.send(iv)
    c2 = bytearray()
    c2 += ciphertext[:-1]
    c2 += bytes([ciphertext[-1] ^ 1])
    server.send(c2)
    response = server.recv(1024)
    server.close()
    print("Oracle said: "+response.decode())

def guess_byte(p,ciphertext,block_size):
    # p and c must have the same length
    padding_value = len(p)+1
    print("pad="+str(padding_value))
    n = num_blocks(ciphertext,block_size)
    print("n="+str(n))
    current_byte_index= len(ciphertext)-1 -block_size - len(p)
    print("current="+str(current_byte_index))

    # print(p)
    # print(c)
    p_prime = 0
    for i in range(0,256):
        # print(i)
        ca = bytearray()
        ca += ciphertext[:current_byte_index]
        ca += i.to_bytes(1,byteorder='big')

        # print(ca)
        for x in p:
            ca += (x ^ padding_value).to_bytes(1,byteorder='big')
        # print(ca)
        ca += get_nth_block(ciphertext,n-1,block_size)
        # print(ca)
        # print("          "+str(ciphertext))

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(ca)
        response = server.recv(1024)

        # print(response)

        if response == b'OK':
            print("found",end=' ')
            print(i)

            p_prime = padding_value ^ i
            # print(p_prime)
            # print(ciphertext[current_byte_index])
            # print(p_prime ^ ciphertext[current_byte_index])
            # c.insert(0,i)
            p.insert(0,p_prime)
            # print(p)
            # print(type(p_prime))
            # x= bytes([p_prime ^ ciphertext[current_byte_index]])
            break

    return bytes([p_prime ^ ciphertext[current_byte_index]])
    # return x
            # print(ciphertext[current_byte_index])

            # print(p2)
            # print(pn14)

def guess_byte_first_block(p,ciphertext,block_size):
    # p and c must have the same length
    padding_value = len(p)+1
    # print("pad="+str(padding_value))
    current_byte_index= block_size - len(p)-1
    # print("current="+str(current_byte_index))

    # print(p)
    # print(c)

    for i in range(0,256):
        # print(i)
        iv_ca = bytearray()
        iv_ca += iv[:current_byte_index]
        iv_ca += i.to_bytes(1,byteorder='big')

        # print(iv_ca)
        for x in p:
            iv_ca += (x ^ padding_value).to_bytes(1,byteorder='big')
        # print(iv_ca)
        # iv_ca += get_nth_block(ciphertext,n-1,block_size)
        # print(iv_ca)
        # print("          "+str(ciphertext))

        server = remote(HOST, PORT)
        server.send(iv_ca)
        server.send(ciphertext)
        response = server.recv(1024)

        # print(response)

        if response == b'OK':
            print("found",end=' ')
            print(i)

            p_prime = padding_value ^ i
            # c.insert(0,i)
            p.insert(0,p_prime)
            break

    return bytes([p_prime ^ iv[current_byte_index]])
            # print(ciphertext[current_byte_index])
            # print(p2)
            # print(pn14)

if __name__ == '__main__':

    check_oracle_good_padding()
    check_oracle_bad_padding()

    n = num_blocks(ciphertext,AES.block_size)
    plaintext = bytearray()

    #for all blocks but the first one (where we need to act on the IV)
    for i in range(1,n):
        c = []
        p = []

        #for all the bytes in the block
        for j in range(0,AES.block_size):
            #add at the beginning of the bytearray the new byte
            plaintext[0:0] = guess_byte(p,ciphertext,AES.block_size)
            print(plaintext)
        ciphertext = ciphertext[:-AES.block_size]


    #guess
    print(len(ciphertext))
    c = []
    p = []
    for i in range(0,AES.block_size):
        plaintext[0:0] = guess_byte_first_block(p,ciphertext,AES.block_size)


    print("Found the plaintext: " + str(plaintext))
