#!/bin/bash

N=0
while true; do
  N=$((N + 1))
  #Lanza el exploit
  python3 mini.py | ./vuln_aslr
  # python3 -c "print('hola')"
  if [ $? -eq 0 ]; then
    echo "Success on try #$N"
    break
  fi
  echo "Failed on try #$N"
done
