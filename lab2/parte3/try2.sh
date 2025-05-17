#!/bin/bash

length=1

while true; do
  payload=$(head -c $length </dev/zero | tr '\0' 'A')
  echo "[*] Enviando $length bytes..."
  echo $payload

  # Enviar el payload por nc (netcat)
  echo "$payload" | nc -w 2 localhost 9999

  if [ $? -ne 0 ]; then
    echo "[!] El servidor ha dejado de responder con $length bytes."
    break
  fi

  length=$((length + 1))
    sleep 0.5
done
