#!/bin/bash

sed -i -e 's/data_flowvoid/data_flow/g' $1/*/*.c
sed -i -e 's/data_flow void/data_flow/g' $1/*/*.c
