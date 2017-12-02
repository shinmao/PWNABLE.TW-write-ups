## Challenge:
1. Use IDA pro but cannot get the source code.
2. ROPgadgets are so little.
3. static linked so no ret2libc.
4. Where are our input?

## Solve:
1. From ASM code, we can get that there is system write function in the program.
2. With GDB, we can see our input on stack. The protection are closed, so if we can put the shellcode on stack and return to it....
3. Use the sys-write gadget to leak the stack address.  

## Exploit:
1. The gadget: mov ecx, esp in syswrite can write the data in user buffer into stdout, so we can get esp = stack address.
2. We already have stack address, input our shellcode and return to it.  
That's what we want!  

## Still some problems?
1. I can't use sendline but just can send() in the first leak side....
