#encrypt a message with AES256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

key = get_random_bytes(32) #AES256

cipher = AES.new(key, AES.MODE_CBC) #IV automatically generated at random
IV = cipher.iv


plaintext = b'This is the AES plaintext!'
print(AES.block_size)

padded_plain = pad(plaintext,AES.block_size) #PKCS5
print(padded_plain)

# ciphertext = cipher.encrypt(padded_plain)



f_input = open("2.chacha20_live.py","rb")

ciphertext = cipher.encrypt(pad(f_input.read(),AES.block_size))
print(ciphertext)

########################33
# we are at the recipient

cipher_dec = AES.new(key,AES.MODE_CBC)

decrypted = cipher_dec.decrypt(ciphertext)
print(unpad(decrypted,AES.block_size))

