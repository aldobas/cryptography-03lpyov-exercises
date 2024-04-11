import base64

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


print(AES.key_size)
print(AES.key_size[2])

key = get_random_bytes(AES.key_size[2])
iv = get_random_bytes(AES.block_size)


data = b'These data are to be encrypted!!'   #  32 bytes, no need for padding
print(len(data))
cipher_enc = AES.new(key, AES.MODE_CBC, iv)
ct = cipher_enc.encrypt(data)

print(len(ct))

cipher_dec = AES.new(key, AES.MODE_CBC, iv)
pt = cipher_dec.decrypt(ct)
print(pt)





# encryption + padding
data = b'Unaligned data to cipher'   # 24 bytes, will need padding
cipher_enc = AES.new(key, AES.MODE_CBC, iv)
padded_data = pad(data,AES.block_size)
print(padded_data)
ct = cipher_enc.encrypt(padded_data)

#print Base64
print(base64.b64encode(ct).decode())


#decryption + unpadding
cipher_dec = AES.new(key, AES.MODE_CBC, iv)
decrypted_data = cipher_dec.decrypt(ct)
print(decrypted_data)
pt = unpad(decrypted_data, AES.block_size)
assert(data == pt)
