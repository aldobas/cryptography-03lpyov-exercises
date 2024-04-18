from Crypto.Cipher import AES
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *


from myconfig import HOST,PORT
from mydata import cbc_oracle_iv as iv
from mydata import cbc_oracle_ciphertext as ciphertext


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

def guess_byte(p,c,ciphertext,block_size):
    # p and c must have the same length
    padding_value = len(p)+1
    print("pad="+str(padding_value))
    n = num_blocks(ciphertext,block_size)
    print("n="+str(n))
    current_byte_index= len(ciphertext)-1 -block_size - len(p)
    print("current="+str(current_byte_index))

    # print(p)
    # print(c)
    plain = b'\x00'
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
            plain = bytes([p_prime ^ ciphertext[current_byte_index]])
            if plain == b'\x01': #this is not sufficient in the general case, onyl wokrs for the last byte and not always
                continue
            # print(p_prime)
            # print(ciphertext[current_byte_index])
            # print(p_prime ^ ciphertext[current_byte_index])
            c.insert(0,i)
            p.insert(0,p_prime)
            # print(p)
            # print(type(p_prime))
            # x= bytes([p_prime ^ ciphertext[current_byte_index]])
            # break


    return plain

def guess_byte_first_block(p,c,ciphertext,block_size):
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
        server.close()
        # print(response)

        if response == b'OK':
            print("found",end=' ')
            print(i)

            p_prime = padding_value ^ i
            c.insert(0,i)
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
    for i in range(1,n):
        c = []
        p = []

        for j in range(0,AES.block_size):
            plaintext[0:0] = guess_byte(p,c,ciphertext,AES.block_size)
            print(plaintext)
        ciphertext = ciphertext[:-AES.block_size]


    print(len(ciphertext))
    c = []
    p = []
    for i in range(0,AES.block_size):
        plaintext[0:0] = guess_byte_first_block(p,c,ciphertext,AES.block_size)
    # plaintext[0:0] = plain
    # plaintext[0:0] = guess_byte(p,c,ciphertext,AES.block_size)
    print(plaintext)
