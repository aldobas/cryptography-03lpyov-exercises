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

def get_last_block(ciphertext, block_size):
    return ciphertext[-block_size:]

def num_blocks(ciphertext, block_size):
    return math.ceil(len(ciphertext)/block_size)

#first block is 0
def get_nth_block(ciphertext, n, block_size):
    return ciphertext[(n)*block_size:(n+1)*block_size]

#first block is 0
def get_block_range(ciphertext, n1, n2, block_size):
    return ciphertext[(n1)*block_size:(n2-1)*block_size]

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


if __name__ == '__main__':

    print("CIPEHRTEXT"+str(ciphertext))
    print("CIPEHRTEXT"+str(iv))

    check_oracle_good_padding()
    check_oracle_bad_padding()


    # start = ciphertext[:-2*AES.block_size]
    # prev = ciphertext[-2*AES.block_size:-AES.block_size]
    # last = ciphertext[-AES.block_size:]

    n = num_blocks(ciphertext,AES.block_size)
    print(n)
    start = get_n_blocks_from_m(ciphertext,n-2,0,AES.block_size)
    prev = get_nth_block(ciphertext,n-2,AES.block_size)
    last = get_nth_block(ciphertext,n-1,AES.block_size)

    ba = bytearray()
    ba += start
    ba += prev
    ba += last
    print(ba)
    print("          "+str(ciphertext))
    print(start)
    print(prev)
    print(last)

    if ciphertext == ba:
        print("Split OK")
    else:
        print("Split NO")


    # gussing first byte
    for c1 in range(0,256):
        # print(c1)
        server = remote(HOST, PORT)
        server.send(iv)

        ca = bytearray()
        ca+=start
        ca+=prev[:-1]
        # print(prev)
        # print(prev[:-1])
        ca+=c1.to_bytes(1,byteorder='big')
        # print(c1.to_bytes(1,byteorder='big'))
        ca+=last
        # print("Sending:" + str(ca))
        # print("          "+str(ciphertext))
        # print(ca)

        server.send(ca)
        response = server.recv(1024)
        # print(response)
        if response == b'OK': # padding is OK = \x01
            print("found",end=' ')
            print("guessed="+str(c1))

            p1 = 1 ^ c1
            # c.insert(0,c1)
            # p.insert(0,p1)

            pn15 = bytes([p1 ^ prev[-1]])
            print("original=" + str(prev[-1]))
            print("p prime="+str(p1))
            print(type(p1))
            print("plain="+str(pn15))
            # break

    plaintext = bytearray()
    plaintext += pn15
    print("plaintext="+str(plaintext))


    # gussing second byte
    # second byte --> padding must be \x02 \x02
    # first compute the last byte
    c1 = p1 ^ 2 # 1 ^ 2 ^ c1
    print(c1)


    # current_byte_index = -AES.block_size-2
    # # starting part up to current_byte_index
    # # guess
    # # adapt the previously guessed byte(s)
    # # add the last block
    # print(ciphertext)
    # for c2 in range(0,256):
    #     print(c2)
    #     ca = bytearray()
    #     ca += ciphertext[:current_byte_index]
    #     ca += c2.to_bytes(1,byteorder='big')
    #     ca += c1.to_bytes(1,byteorder='big')
    #     ca+=get_nth_block(ciphertext,n-1,AES.block_size)
    #     print("          " + str(ciphertext))
    #     print(ca)
    #
    #     server = remote(HOST, PORT)
    #     server.send(iv)
    #     server.send(ca)
    #     response = server.recv(1024)
    #     print(response)
    #
    #     if response == b'OK': # padding is OK = \x02\x02
    #         print("found",end=' ')
    #         print(c2)
    #
    #         p2 = 2 ^ c2
    #
    #         pn14 = bytes([p2 ^ ciphertext[current_byte_index]])
    #         print(ciphertext[current_byte_index])
    #         print(p2)
    #         print(pn14)
    #         break
    #
    # plaintext[0:0] = pn14
    # print(plaintext)
    # print(c)


    print(plaintext)
