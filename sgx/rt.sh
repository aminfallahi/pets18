#!/bin/bash
sudo trace-cmd record -o tracebench/$1.dat -e $2 &
./app
fg
