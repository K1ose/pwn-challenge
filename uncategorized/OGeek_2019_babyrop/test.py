from pwn import *
libc = ELF("libc-2.23.so")

libc_binsh = next(libc.search("/bin/sh"))
print(hex(libc_binsh))
