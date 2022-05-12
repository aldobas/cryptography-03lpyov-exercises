import json
from base64 import b64encode,b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes



# here we are the senders / originators
header = b"this is the authentication only part"
data = b"this is the secret part"

key = get_random_bytes(AES.key_size[2])
cipher = AES.new(key, AES.MODE_GCM)
cipher.update(header) #this is to load the data that only need authentication and integrity
ciphertext, tag = cipher.encrypt_and_digest(data) # this is to add the data to also encrypt and get the outputs

json_k =  [ 'nonce', 'header', 'ciphertext', 'tag' ]
outputs = [cipher.nonce, header, ciphertext, tag]
json_v = [ b64encode(x).decode() for x in outputs ]
json_object  = json.dumps(dict(zip(json_k, json_v)))
print(json_object)


# here we are the verifiers / receivers
try:
    b64 = json.loads(json_object)
    json_k = ['nonce','header','ciphertext','tag']
    jv = {k:b64decode(b64[k]) for k in json_k}

    cipher_receiver = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
    cipher_receiver.update(jv['header'])
    plaintext = cipher_receiver.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    print("The message was: " + plaintext.decode('utf-8')+" and is authentic.")
except (ValueError, KeyError):
    print("Incorrect decryption")
