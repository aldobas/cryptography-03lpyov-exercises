from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

if __name__ == '__main__':

    print(get_random_bytes(40))

    print(get_random_bytes(AES.block_size))

