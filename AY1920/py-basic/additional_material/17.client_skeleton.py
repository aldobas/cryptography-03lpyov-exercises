from pwn import *
import sys

ADDRESS = "localhost"
PORT = 12343

msg = sys.argv[1]

q = remote(ADDRESS, PORT)
print("Sending: "+msg)
q.send(msg)
y = q.recv(1024).decode('utf-8')
q.close()

print("Receiving: "+y)

if y == msg:
    print("Echo succeeded!")
else:
    print("Echo failed!")

