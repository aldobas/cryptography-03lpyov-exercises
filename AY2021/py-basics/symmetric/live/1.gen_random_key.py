#import libraries
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

#generate a random key
random = get_random_bytes(16)
print(random)
print(type(random))

#b64encode
print(b64encode(random))

#print b64encoded


