import hashlib
import hmac
from Crypto.Random import get_random_bytes

msg = b'This is the message'
key = get_random_bytes(32)

blake = hashlib.blake2b(key=key, digest_size=32)
blake.update(msg)
print("BLAKE = " + blake.hexdigest())

####################

mac_object = hmac.new(key, msg, hashlib.sha256)
hmac_sha256 = mac_object.hexdigest()
print("HMAC-SHA256   = " + hmac_sha256)

msg1 = b'This is the new message'
mac_object_1 = hmac.new(key, msg1, hashlib.sha256)
hmac_sha256_1 = mac_object_1.hexdigest()
print("HMAC-SHA256_1 = " + hmac_sha256_1)

if hmac.compare_digest(mac_object_1.digest(), mac_object.digest()):
    print("HMAC correctly verified: messages are identical")
else:
    print("HMAC are different")
