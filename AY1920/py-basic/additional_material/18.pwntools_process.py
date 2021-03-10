from pwn import *

context.update(arch='amd64', os='linux')
io = process('sh')
io.sendline('echo Hello, world')
print(io.recvline())
