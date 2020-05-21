from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from mysecrets import aes_key

plaintext = b'This is the secret message to encrypt'


# key = get_random_bytes(32) #key for AES256
iv = get_random_bytes(AES.block_size)

cipher = AES.new(aes_key,AES.MODE_CBC,iv)

padded_data = pad(plaintext,AES.block_size) #PKCS#7 01 0202 030303
print(padded_data)
ciphertext = cipher.encrypt(padded_data)
print(ciphertext)
print(cipher.iv)


###############
# at the recipient
# again import from mysecrets the aes_key

cipher2 = AES.new(aes_key, AES.MODE_CBC, cipher.iv)
decrypted_data = cipher2.decrypt(ciphertext)
print(decrypted_data)
pt = unpad(decrypted_data, AES.block_size)
assert(plaintext == pt)
