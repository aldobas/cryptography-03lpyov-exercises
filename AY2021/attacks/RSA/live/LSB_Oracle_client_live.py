import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwnlib.tubes.remote import remote

from mysecrets import HOST,PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext

import decimal

def to_bytes(m,l=n.bit_length()):
    return int.to_bytes(m, l, byteorder='big')

def to_int(b):
    return int.from_bytes(b,byteorder='big')

def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")



if __name__ == '__main__':

    n_len = n.bit_length() #1024



    decimal.getcontext().prec = n_len+1
    upper_bound = decimal.Decimal(n)
    lower_bound = decimal.Decimal(0)
    print_bounds(lower_bound,upper_bound)

    c = ciphertext
    for i in range(n_len):
        c = (pow(2,e,n)*c) % n

        oracle = remote(HOST,PORT)
        oracle.send(to_bytes(c,n_len))
        ans = oracle.recv(1024)

        if ans[0] == 1:
            lower_bound = (lower_bound+upper_bound)/2
        else:

            upper_bound = (lower_bound+upper_bound)/2
        print_bounds(lower_bound,upper_bound)

    # lower_bound == upper_bound == decrypted message
    print(to_bytes(int(lower_bound),n_len).decode())
    print(to_bytes(int(upper_bound), n_len).decode())
