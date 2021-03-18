from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

AES256_KEY_SIZE = 32 # forces AES256

data = b'Unaligned data to cipher'   # 24 bytes
key = get_random_bytes(AES256_KEY_SIZE)
iv = get_random_bytes(AES.block_size)

cipher1 = AES.new(key, AES.MODE_CBC, iv)
padded_data = pad(data,AES.block_size)
print(padded_data)
ct = cipher1.encrypt(padded_data)

#decryption
cipher2 = AES.new(key, AES.MODE_CBC, iv)
decrypted_data = cipher2.decrypt(ct)
print(decrypted_data)
pt = unpad(decrypted_data, AES.block_size)
assert(data == pt)
