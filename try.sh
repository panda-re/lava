#!/bin/bash

while [ $? -ne 139 ]; do
    rm target_injections/elfparser/inputs/hola-fuzzed-*
    rm -rf target_injections/elfparser/bugs/0/
    ./scripts/lava.sh -i 1 -n 2000 elfparser
    #gdb --ex run --args ./target_injections/speedpng/bugs/0/speedpng/speedpng ./target_injections/speedpng/inputs/zip-fuzzed-$(cat target_injections/speedpng/logs/lavaTool-speedpng-c-stdout.log|tail -n 1|awk '{print $5}').png
    ./target_injections/elfparser/bugs/0/elfparser/elfparser ./target_injections/elfparser/inputs/hola-fuzzed-$(cat target_injections/elfparser/logs/lavaTool-elfparser-c-stdout.log|tail -n 1|awk '{print $5}')
done
