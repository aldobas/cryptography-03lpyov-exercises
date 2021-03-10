from Crypto.PublicKey import RSA

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwnlib.tubes.remote import remote

from mysecrets import HOST,PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext

from mysecrets import lsb_d
from mysecrets import lsb_plaintext as plaintext


def to_bytes(m,l=n.bit_length()):
    return int.to_bytes(m, l, byteorder='big')

def to_int(b):
    return int.from_bytes(b,byteorder='big')

def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")

lower_bound = 0
upper_bound = n


m = ciphertext

c1 = 0
c0 = 0
cx = 0
print_bounds(lower_bound,upper_bound)
for i in range(n.bit_length()):
    server = remote(HOST, PORT)

    m = (pow(2, e, n) * m) % n
    server.send(to_bytes(m))
    bit = server.recv(1024)
    print(bit)

    if  bit[0] == 1:
        lower_bound = (upper_bound + lower_bound) // 2
        c1+=1
    else:
        upper_bound = (upper_bound + lower_bound) // 2
        c0+=1
    print_bounds(lower_bound, upper_bound)
    if (upper_bound + lower_bound)%2 == 1:
        cx +=1

    server.close()

print(n.bit_length())
print(to_bytes(lower_bound,n.bit_length()).decode())
# print(to_bytes(upper_bound,n.bit_length()).decode())

print(c1)
print(c0)
print(cx)

print(plaintext-lower_bound)
