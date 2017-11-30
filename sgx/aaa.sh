#!/bin/bash
sudo trace-cmd record -o tracebench/exp-2.dat -e exceptions
sudo trace-cmd record -o tracebench/irq-1.dat -e irq
sudo trace-cmd record -o tracebench/irq-2.dat -e irq
sudo trace-cmd record -o tracebench/kmem-1.dat -e kmem
sudo trace-cmd record -o tracebench/kmem-2.dat -e kmem
sudo trace-cmd record -o tracebench/pagemap-1.dat -e pagemap
sudo trace-cmd record -o tracebench/pagemap-2.dat -e pagemap
sudo trace-cmd record -o tracebench/random-1.dat -e random
sudo trace-cmd record -o tracebench/random-2.dat -e random
sudo trace-cmd record -o tracebench/tlb-1.dat -e tlb
sudo trace-cmd record -o tracebench/tlb-2.dat -e tlb
