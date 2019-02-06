#!/bin/bash

sed -i -e 's/data_flowvoid/data_flow/g' $1/*/*.c
