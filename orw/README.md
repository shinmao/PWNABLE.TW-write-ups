## Start

### Challenges
This is just a simple shellcode problem.  
  
### Solution  
I separate my shellcode to four parts.  
read -> open -> read -> write  
with system function  
read from my input  
open my input  
read the content into stream  
write the content into stdout.  
 
