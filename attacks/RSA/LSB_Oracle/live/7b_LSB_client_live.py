from Crypto.PublicKey import RSA

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwnlib.tubes.remote import remote

from mysecrets import HOST,PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext
from mysecrets import lsb_plaintext

def to_bytes(m,l=n.bit_length()):
    return int.to_bytes(m, l, byteorder='big')

def to_int(b):
    return int.from_bytes(b,byteorder='big')

def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")


# test the connection
# server = remote(HOST, PORT)
# server.send(to_bytes(ciphertext))
# bit = server.recv(1024)
# print(bit)
# server.close()




#loop
upper_bound = n
lower_bound = 0
print_bounds(lower_bound,upper_bound)

k = pow(2,e,n)

m = ciphertext
c1 = 0
c0 = 0
cx = 0
for i in range(n.bit_length()):
    m = (k * m) % n

    #interact with the LSB Oracle
    server = remote(HOST, PORT)
    server.send(to_bytes(m))
    bit = server.recv(1024)
    server.close()
    print(bit)

    if bit[0] == 1:
        lower_bound = (upper_bound+lower_bound) // 2
        c1 += 1
    else:
        upper_bound = (upper_bound+lower_bound) // 2
        c0 += 1
    print_bounds(lower_bound,upper_bound)
    if (upper_bound+lower_bound) % 2:
        cx +=1

print(to_bytes(lower_bound,n.bit_length()).decode())
print(to_bytes(upper_bound,n.bit_length()).decode())

print(lsb_plaintext - lower_bound)

print(c1)
print(c0)
print(cx)
