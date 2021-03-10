from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.Padding import pad


#Short-Key Cipher: encryption and decryption functions
def shortkey8_enc(key, message, iv):
    actual_key = bytes.fromhex(key)*16
    cipher = AES.new(actual_key,AES.MODE_CBC, iv)
    return cipher.encrypt(pad(message,AES.block_size))

def shortkey8_dec(key, message, iv):
    actual_key = bytes.fromhex(key)*16
    cipher = AES.new(actual_key,AES.MODE_CBC, iv)
    return cipher.decrypt(message)

def double8_enc(key1, key2, message, iv):
    actual_key1 = bytes.fromhex(key1)*16
    actual_key2 = bytes.fromhex(key2)*16
    cipher1 = AES.new(actual_key1,AES.MODE_CBC, iv)
    cipher2 = AES.new(actual_key2,AES.MODE_CBC, iv)
    return cipher2.encrypt(cipher1.encrypt(pad(message,AES.block_size)))



if __name__ == '__main__':

    # generate two random 1-byte keys in an OpenSSL-like format
    # (string of hexadecimal digits without leading 0x)
    # e.g., "aa" "07" "f4"
    key1 = format(randint(0, 256), '02x')
    key2 = format(randint(0, 256), '02x')
    print(key1)
    print(key2)

    #generate a random IV
    iv = get_random_bytes(16)
    print(iv)

    # generate a plaintext and double-encrypt it with a short-key cipher
    plaintext = b'This is just a string that has not a meaning'
    ciphertext = double8_enc(key1,key2,plaintext,iv)


    # number of keys to explore with the used cipher
    # 8 bit key -> 256 keys
    # in double encryption -> 65535 keys
    NUM_KEYS = 256

    #build the dictionary from the plaintext: HashMap
    dict = {}
    # look for ciphertext: comparison done for ciphertexts
    # keys: ciphertexts --> values: keys used to obtain that ciphertext from the plaintext
    for i in range(0,NUM_KEYS): #1 --> 0x01 --> "01" to the short8_enc
        dict_key = shortkey8_enc(format(i,'02x'),plaintext,iv)
        dict[dict_key] = i
        #256 encryptions
    #dictionary with all the possible ciphertext
    # 8 bit keys --> impossible with longer key

    #check if you find the intermediate artifact
    #opposite direction

    for i in range(0,NUM_KEYS):
        intermediate_artifact = shortkey8_dec(format(i,'02x'),ciphertext,iv)

        if intermediate_artifact in dict.keys():
            print("k1 = ", end=' ')
            print(dict.get(intermediate_artifact))
            print("k2 = "+str(i))
    # wrost case: 256 iteration: 8+1 security
