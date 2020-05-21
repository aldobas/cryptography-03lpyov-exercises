from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import json

msg = b'This is the message to use to compute a MAC'

key = get_random_bytes(32)

hmac_generator = HMAC.new(key,digestmod=SHA256)

hmac_generator.update(msg[:10])
hmac_generator.update(msg[10:])

mac = hmac_generator.hexdigest()

print(mac)

json_dict = {"message":msg.decode('utf-8'), "MAC":mac}
json_object = json.dumps(json_dict)
print(json_object)



###################################
# here is teh recipient
# we shared the key securely: key
# recipient receives the json object through a public channel


b64 = json.loads(json_object)
hmac_verifier = HMAC.new(key,digestmod=SHA256)
# hmac_verifier.update(b64["message"].encode('utf-8'))
hmac_verifier.update(b'a different sequence of bytes')

try:
    hmac_verifier.hexverify(b64["MAC"])
    print("The message is authentic")

except ValueError:
    print("The message or the key are wrong")
