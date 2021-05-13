from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

if __name__ == '__main__':
    print(get_random_bytes(AES.block_size))

