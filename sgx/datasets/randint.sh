#!/bin/bash
for i in `seq 1 100000`; do
r=`od -An -N4 -i < /dev/urandom`
echo $((r%1000000)) >> $1

done
