from pwn import *

io = remote('google.com', 80)
io.send('get /\r\n\r\n')
print(io.recvline())

#import requests
