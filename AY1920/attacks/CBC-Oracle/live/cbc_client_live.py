from Crypto.Cipher import AES
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'  # reduce logging info of pwntools on stdin
from pwn import *
import string

from mysecrets import HOST,PORT, cbc_oracle_iv as iv
from mysecrets import cbc_oracle_ciphertext as ciphertext

def num_blocks(ciphertext, block_size):
    return math.ceil(len(ciphertext)/block_size)

#first block is 0
def get_nth_block(ciphertext, n, block_size):
    return ciphertext[(n)*block_size:(n+1)*block_size]

def get_n_blocks_from_m(ciphertext, n, m, block_size):
    return ciphertext[(m)*block_size:(m+n)*block_size]


def guess_byte(p,c, ciphertext, block_size):

    #build the payload
    # current index
    # append up to the index from the ciphertext
    # byte to guess
    # process all the previously guessed bytes in the block

    # if I already guessed y bytes --> there are y elements in p
    # if I already guessed y bytes --> padding now will be y+1

    padding_value = len(p) + 1
    n = num_blocks(ciphertext,AES.block_size)

    # starting part --> 0 - n-2 | (16-len(p) bytes of b n-1) | guessing value | len(p) | last block
    #                                                                     1            16
    current_byte_index = len(ciphertext) -1 -block_size - len(p)

    plain = b'\x00'
    p_prime = 0
    for i in range(256):
        #build the payload
        # current index
        # append up to the index from the ciphertext
        # byte to guess
        # process all the previously guessed bytes in the block



        ca = bytearray()
        ca += ciphertext[:current_byte_index]
        ca += i.to_bytes(1,byteorder='big')

        for x in p:
            ca += (x ^ padding_value).to_bytes(1,byteorder='big')

        ca += get_nth_block(ciphertext,n-1,AES.block_size)



        if response == b'OK':
            print("found =",end=' ')
            print(i)

            p_prime = padding_value ^ i
            plain = bytes([p_prime ^ ciphertext[current_byte_index]]) #  prev[-1] --> c15
            # print(c_prime15)
            # print(p_prime15)
            # print(pn15)
            c.insert(0,i)
            p.insert(0,p_prime)
            break
    return plain


if __name__ == '__main__':
    server = remote(HOST,PORT)
    server.send(iv)
    server.send(ciphertext)
    response = server.recv(1024)
    print("Oracle said: " + response.decode())

    server = remote(HOST,PORT)
    server.send(iv)
    c2 = bytearray()
    c2 += ciphertext[:-1]
    c2 += bytes([ciphertext[-1] ^ 1])
    server.send(c2)
    response = server.recv(1024)
    print("Oracle said: " + response.decode())

    # split the ciphertext
    n = num_blocks(ciphertext,AES.block_size)
    start = get_n_blocks_from_m(ciphertext,n-2,0,AES.block_size)
    prev = get_nth_block(ciphertext,n-2,AES.block_size)
    last = get_nth_block(ciphertext,n-1,AES.block_size)

    ba = bytearray()
    ba += start
    ba += prev
    ba += last

    print(ciphertext)
    print(ba)

    # assemble the payload
    # start + 15 bytes of the prev + guess value + last
    # send to server
    # check if OK then obtain the payload

    plaintext = bytearray()

    for c_prime15 in range(0,256):
        server =remote(HOST,PORT)
        server.send(iv)

        #build the payload
        ca = bytearray()
        ca += start
        ca += prev[:-1]
        ca += c_prime15.to_bytes(1,byteorder='big')
        ca += last

        # print(ca)

        # talk to the Oracle
        server.send(ca)
        response= server.recv(1024)

        # if the padding was OK
        if response == b'OK':
            print("found =",end=' ')
            print(c_prime15)

            p_prime15 = 1 ^ c_prime15
            pn15 = bytes([p_prime15 ^ prev[-1]]) #  prev[-1] --> c15
            print(c_prime15)
            print(p_prime15)
            print(pn15)
            break

    plaintext += pn15
    print("plaintext = " + str(plaintext))


    # guessing the second byte of the block n

    c_second15 = p_prime15 ^ 2

    # build the payload
    # starting part --> 0 - n-2 | (16-len(p) bytes of b n-1) | guessing value | len(p) | last block
    #                                                                     1            16

    current_byte_index = -AES.block_size -1 -1

    for c_prime14 in range(0,256):
        ca = bytearray()
        ca += ciphertext[:current_byte_index]
        ca += c_prime14.to_bytes(1,byteorder='big')
        ca += c_second15.to_bytes(1,byteorder='big')
        ca += get_nth_block(ciphertext,n-1,AES.block_size)


        server =remote(HOST,PORT)
        server.send(iv)
        # talk to the Oracle
        server.send(ca)
        response= server.recv(1024)

        # if the padding was OK
        if response == b'OK':
            print("found =",end=' ')
            print(c_prime14)

            p_prime14 = 2 ^ c_prime14

            pn14 = bytes([p_prime14 ^ ciphertext[current_byte_index]]) #  prev[-1] --> c15
            print(c_prime14)
            print(p_prime14)
            print(pn14)
            break

    plaintext[0:0] += pn14
    print("plaintext = " + str(plaintext))
