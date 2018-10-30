#!/bin/bash

# Run in a loop on the host. When we see _tests/*/built, we run fninstr.py

cd $1
targets_c=$2
targets=0
rm -f */built;

echo "Started, ready to fninstr on $targets_c $dir targets"
while true; do
    for dir in ./*; do
        if [ -f "$dir/built" ]; then
            echo "Built exists, generate fnwl"
            python ../../../scripts/fninstr.py -d "./$dir/$dir.c.fn" -o "$dir/$dir.fnwl"
            echo "Done!"
            rm "$dir/built"
            targets=$((targets+1))
            if [ $targets -eq $targets_c ]; then
                echo "Finished"
                exit 1
            fi
        fi
    done
done
