import base64
import json
from Crypto.Hash import HMAC, SHA512
from Crypto.Random import get_random_bytes

from Crypto.Hash import HMAC, SHA512


# gen message

msg = b'This is the message. This is the message. This is the message. This is the message. '

#instanciate the HMAC object
key = get_random_bytes(16)
hmac_gen = HMAC.new(digestmod=SHA512, key = key)
hmac_gen.update(msg[:20])
hmac_gen.update(msg[20:])

print(hmac_gen.hexdigest())

#pack data into a JSON object
# MAC, original message

print(hmac_gen.digest())
print(hmac_gen.hexdigest()) # 1 byte into 2 characters : 100%


mac = base64.b64encode(hmac_gen.digest()).decode() # mac is a string
print(mac) # 6 bits into 8 bits: 33%

packed_data = json.dumps({"message": msg.decode(), "MAC":mac, "algo": "SHA512"})

print(packed_data)

# here we are at the receiver
######################################################
# ASSUMPTION: we have securely exchanged the secret key
# packet_data are received
#unpack data

unpacked_data = json.loads(packed_data)
print(type(unpacked_data["message"]))

print(unpacked_data["MAC"])

hmac_verifier = HMAC.new(key=key,digestmod=SHA512)
hmac_verifier.update(unpacked_data["message"].encode())
print(hmac_verifier.hexdigest())

# verify MAC

print(type(base64.b64decode(unpacked_data["MAC"])))

try:
    hmac_verifier.verify(base64.b64decode(unpacked_data["MAC"]))
except ValueError:
    print("ERROR: MAC verification failed")

print("MAC verification OK")


#change the received MAC: bytearray
# then check it again
# bytes are unmodifiable
modified_MAC = bytearray( base64.b64decode(unpacked_data["MAC"]) )

print(modified_MAC[0])
modified_MAC[0] += 1
print(modified_MAC[0])


try:
    hmac_verifier.verify(base64.b64decode(modified_MAC))
except ValueError:
    print("ERROR: MAC verification failed")

print("MAC verification OK")
