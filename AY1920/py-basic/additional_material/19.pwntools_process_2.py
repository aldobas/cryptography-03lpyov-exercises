from pwn import *

io = process(['sh', '-c', 'echo $MYENV'], env={'MYENV': 'MYVAL'})
print(io.recvline())
